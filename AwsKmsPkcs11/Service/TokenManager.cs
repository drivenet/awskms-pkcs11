using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace AwsKmsPkcs11.Service
{
    public sealed class TokenManager : IDisposable
    {
        private static readonly Pkcs11InteropFactories Factories = new Pkcs11InteropFactories();

        private readonly object _lock = new object();
        private readonly IOptionsMonitor<TokenOptions> _options;
        private readonly ILogger _logger;
        private IPkcs11Library? _library;

        public TokenManager(IOptionsMonitor<TokenOptions> options, ILogger<TokenManager> logger)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        private IPkcs11Library? Library
        {
            get
            {
                var library = _library;
                if (library is null)
                {
                    var libraryPath = GetLibraryPath();
                    lock (_lock)
                    {
                        library = _library;
                        if (library is null)
                        {
                            _library = library = Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Factories, libraryPath, AppType.MultiThreaded);
                            if (library is null)
                            {
                                _logger.LogError(EventIds.LibraryLoadFailed, "Failed to load PKCS#11 library \"{LibraryPath}\".", libraryPath);
                            }
                        }
                    }
                }

                return library;

                static string GetLibraryPath()
                {
                    return Environment.OSVersion.Platform == PlatformID.Win32NT ? "libykcs11-1.dll" : "libykcs11.so";
                }
            }
        }

        public void Dispose() => _library?.Dispose();

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

            return Decrypt(key.KeyId, slot, ciphertext);
        }

        private byte[]? Encrypt(byte keyId, ISlot slot, byte[] plaintext)
        {
            using var session = slot.OpenSession(SessionType.ReadOnly);
            var query = new List<IObjectAttribute>
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { keyId }),
            };

            var key = session.FindAllObjects(query).SingleOrDefault();
            if (key is null)
            {
                _logger.LogWarning(EventIds.NoMatchingKey, "No public key with id {KeyId} on token with serial number \"{SerialNumber}\".", keyId, slot.GetTokenInfo().SerialNumber);
                return null;
            }

            using var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
            _logger.LogInformation(EventIds.Encrypt, "Encrypting with mechanism type {Mechanism} using key with id {KeyId} on token with serial number \"{SerialNumber}\".", mechanism.Type, keyId, slot.GetTokenInfo().SerialNumber);
            return session.Encrypt(mechanism, key, plaintext);
        }

        private byte[]? Decrypt(byte keyId, ISlot slot, byte[] ciphertext)
        {
            var pin = _options.CurrentValue.TokenPin;
            using var session = slot.OpenSession(SessionType.ReadOnly);
            try
            {
                session.Login(CKU.CKU_USER, pin);
            }
            catch (Pkcs11Exception exception) when (exception.RV == CKR.CKR_PIN_INCORRECT)
            {
                _logger.LogError(EventIds.InvalidPin, "Invalid PIN for token with serial number \"{SerialNumber}\".", keyId, slot.GetTokenInfo().SerialNumber);
                return null;
            }

            try
            {
                var query = new List<IObjectAttribute>
                {
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { keyId }),
                };

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

        private ISlot? SelectSlot(string serialNumber)
        {
            var slots = Library?.GetSlotList(SlotsType.WithTokenPresent);
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
            public static readonly EventId LibraryLoadFailed = new EventId(1, nameof(LibraryLoadFailed));
            public static readonly EventId NoMatchingToken = new EventId(2, nameof(NoMatchingToken));
            public static readonly EventId NoMatchingKey = new EventId(3, nameof(NoMatchingKey));
            public static readonly EventId InvalidPin = new EventId(4, nameof(InvalidPin));
            public static readonly EventId Encrypt = new EventId(5, nameof(Encrypt));
            public static readonly EventId Decrypt = new EventId(6, nameof(Decrypt));
        }
    }
}
