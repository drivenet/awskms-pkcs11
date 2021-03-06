﻿using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Extensions.Logging;

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace AwsKmsPkcs11.Service
{
    public sealed class TokenManager : ITokenManager
    {
        private readonly IPkcs11Library _library;
        private readonly ILogger _logger;

        public TokenManager(IPkcs11Library library, ILogger<TokenManager> logger)
        {
            _library = library ?? throw new ArgumentNullException(nameof(library));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public byte[]? Encrypt(KeyDescription key, byte[] plaintext)
        {
            var slot = SelectSlot(key.TokenSerialNumber);
            if (slot is null)
            {
                return null;
            }

            return Encrypt(key.KeyId, slot, plaintext);
        }

        public byte[]? TryDecrypt(KeyDescription key, byte[] ciphertext)
        {
            var slot = SelectSlot(key.TokenSerialNumber);
            if (slot is null)
            {
                return null;
            }

            return Decrypt(key.KeyId, key.TokenPin, slot, ciphertext);
        }

        public bool AreAllKeysValid(IEnumerable<KeyDescription> keys)
        {
            foreach (var group in keys.GroupBy(k => (k.TokenSerialNumber, k.TokenPin), k => k.KeyId))
            {
                var slot = SelectSlot(group.Key.TokenSerialNumber);
                if (slot is null)
                {
                    return false;
                }

                if (!AreKeysValid(slot, group.ToArray(), group.Key.TokenPin))
                {
                    return false;
                }
            }

            return true;
        }

        private static List<IObjectAttribute> QueryPublicKeys(byte[] keyIds, ISession session)
        {
            List<IObjectAttribute> query;
            var objectAttributeFactory = session.Factories.ObjectAttributeFactory;
            query = new List<IObjectAttribute>
            {
                objectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                objectAttributeFactory.Create(CKA.CKA_ID, keyIds),
                objectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                objectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 2048),
            };
            return query;
        }

        private static List<IObjectAttribute> QueryPrivateKeys(byte[] keyIds, ISession session)
        {
            var objectAttributeFactory = session.Factories.ObjectAttributeFactory;
            var query = new List<IObjectAttribute>
            {
                objectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                objectAttributeFactory.Create(CKA.CKA_ID, keyIds),
                objectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            };
            return query;
        }

        private bool AreKeysValid(ISlot slot, byte[] keyIds, string pin)
        {
            using var session = slot.OpenSession(SessionType.ReadOnly);
            var query = QueryPrivateKeys(keyIds, session);
            if (!Login(session, pin, slot))
            {
                return false;
            }

            int count;
            try
            {
                count = session.FindAllObjects(query).Count;
            }
            finally
            {
                session.Logout();
            }

            if (count != keyIds.Length)
            {
                return false;
            }

            query = QueryPublicKeys(keyIds, session);

            count = session.FindAllObjects(query).Count;
            if (count != keyIds.Length)
            {
                return false;
            }

            return true;
        }

        private byte[]? Encrypt(byte keyId, ISlot slot, byte[] plaintext)
        {
            using var session = slot.OpenSession(SessionType.ReadOnly);
            var query = QueryPublicKeys(new[] { keyId }, session);

            var key = session.FindAllObjects(query).SingleOrDefault();
            if (key is null)
            {
                _logger.LogWarning(EventIds.NoMatchingKey, "No RSA 2048-bit public key with id {KeyId} on token with serial number \"{SerialNumber}\".", keyId, slot.GetTokenInfo().SerialNumber);
                return null;
            }

            using var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
            _logger.LogInformation(EventIds.Encrypt, "Encrypting with mechanism type {Mechanism} using key with id {KeyId} on token with serial number \"{SerialNumber}\".", mechanism.Type, keyId, slot.GetTokenInfo().SerialNumber);
            return session.Encrypt(mechanism, key, plaintext);
        }

        private byte[]? Decrypt(byte keyId, string pin, ISlot slot, byte[] ciphertext)
        {
            using var session = slot.OpenSession(SessionType.ReadOnly);
            if (!Login(session, pin, slot))
            {
                return null;
            }

            try
            {
                var query = QueryPrivateKeys(new[] { keyId }, session);
                var key = session.FindAllObjects(query).SingleOrDefault();
                if (key is null)
                {
                    _logger.LogError(EventIds.NoMatchingKey, "No private key with id {KeyId} on token with serial number \"{SerialNumber}\".", keyId, slot.GetTokenInfo().SerialNumber);
                    return null;
                }

                using var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
                _logger.LogInformation(EventIds.Decrypt, "Decrypting with mechanism type {Mechanism} using key with id {KeyId} on token with serial number \"{SerialNumber}\".", mechanism.Type, keyId, slot.GetTokenInfo().SerialNumber);
                return session.Decrypt(mechanism, key, ciphertext);
            }
            finally
            {
                session.Logout();
            }
        }

        private bool Login(ISession session, string pin, ISlot slot)
        {
            try
            {
                session.Login(CKU.CKU_USER, pin);
                return true;
            }
            catch (Pkcs11Exception exception) when (exception.RV == CKR.CKR_PIN_INCORRECT)
            {
                _logger.LogError(EventIds.InvalidPin, "Invalid PIN for token with serial number \"{SerialNumber}\".", slot.GetTokenInfo().SerialNumber);
                return false;
            }
        }

        private ISlot? SelectSlot(string serialNumber)
        {
            var slots = _library.GetSlotList(SlotsType.WithTokenPresent);
            if (slots is null)
            {
                return null;
            }

            foreach (var slot in slots)
            {
                var token = slot.GetTokenInfo();
                if (token.SerialNumber == serialNumber)
                {
                    return slot;
                }
            }

            _logger.LogWarning(EventIds.NoMatchingToken, "No token matching serial number \"{SerialNumber}\".", serialNumber);
            return null;
        }

        private static class EventIds
        {
            public static readonly EventId NoMatchingToken = new EventId(2, nameof(NoMatchingToken));
            public static readonly EventId NoMatchingKey = new EventId(3, nameof(NoMatchingKey));
            public static readonly EventId InvalidPin = new EventId(4, nameof(InvalidPin));
            public static readonly EventId Encrypt = new EventId(5, nameof(Encrypt));
            public static readonly EventId Decrypt = new EventId(6, nameof(Decrypt));
        }
    }
}
