using System;
using System.Collections.Generic;

using Microsoft.Extensions.Logging;

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

using static System.FormattableString;

namespace AwsKmsPkcs11.Service
{
    public sealed partial class LibraryTokenManager : ITokenManager
    {
        private static readonly Pkcs11InteropFactories Factories = new Pkcs11InteropFactories();

        private readonly ILogger<TokenManager> _innerLogger;

        public LibraryTokenManager(ILogger<TokenManager> innerLogger)
        {
            _innerLogger = innerLogger ?? throw new ArgumentNullException(nameof(innerLogger));
        }

        public byte[]? Encrypt(KeyDescription key, byte[] plaintext)
        {
            using var tokenManager = GetTokenManager();
            return tokenManager.Encrypt(key, plaintext);
        }

        public byte[]? TryDecrypt(KeyDescription key, byte[] ciphertext)
        {
            using var tokenManager = GetTokenManager();
            return tokenManager.TryDecrypt(key, ciphertext);
        }

        public bool AreAllKeysValid(IEnumerable<KeyDescription> keys)
        {
            using var tokenManager = GetTokenManager();
            return tokenManager.AreAllKeysValid(keys);
        }

        private static IPkcs11Library LoadLibrary()
        {
            var libraryPath = Environment.OSVersion.Platform == PlatformID.Win32NT ? "libykcs11-1.dll" : "libykcs11.so";
            var library = Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Factories, libraryPath, AppType.SingleThreaded);
            if (library is null)
            {
                throw new DllNotFoundException(Invariant($"Failed to load PKCS#11 library \"{libraryPath}\"."));
            }

            return library;
        }

        private DisposableTokenManager GetTokenManager()
        {
            var library = LoadLibrary();
            try
            {
                return new DisposableTokenManager(new TokenManager(library, _innerLogger), library);
            }
            catch
            {
                library.Dispose();
                throw;
            }
        }
    }
}
