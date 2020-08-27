using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

using static System.FormattableString;

namespace AwsKmsPkcs11.Service
{
    public sealed class TokenManager : IDisposable
    {
        private static readonly Pkcs11InteropFactories Factories = new Pkcs11InteropFactories();

        private readonly object _lock = new object();
        private readonly IOptionsMonitor<TokenOptions> _options;
        private IPkcs11Library? _library;

        public TokenManager(IOptionsMonitor<TokenOptions> options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        private IPkcs11Library Library
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
                        }
                    }

                    if (library is null)
                    {
                        throw new InvalidOperationException(Invariant($"Failed to load PKCS#11 library \"{libraryPath}\"."));
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
            var slot = SelectSlot(key);
            if (slot is null)
            {
                return null;
            }

            return Encrypt(key.KeyId, slot, plaintext);
        }

        public byte[]? TryDecrypt(KeyDescription key, byte[] ciphertext)
        {
            var slot = SelectSlot(key);
            if (slot is null)
            {
                return null;
            }

            return Decrypt(key.KeyId, slot, ciphertext);
        }

        private static byte[]? Encrypt(byte keyId, ISlot slot, byte[] plaintext)
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
                return null;
            }

            using var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
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
                //Incorrect PIN
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
                    return null;
                }

                using var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
                return session.Decrypt(mechanism, key, ciphertext);
            }
            finally
            {
                session.Logout();
            }
        }

        private ISlot? SelectSlot(KeyDescription key)
        {
            var slots = Library.GetSlotList(SlotsType.WithTokenPresent);
            foreach (var slot in slots)
            {
                var token = slot.GetTokenInfo();
                if (token.SerialNumber == key.TokenSerialNumber)
                {
                    return slot;
                }
            }

            return null;
        }
    }
}
