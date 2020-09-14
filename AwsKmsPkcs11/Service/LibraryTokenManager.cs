using System;
using System.Collections.Generic;

using Microsoft.Extensions.Logging;

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

using static System.FormattableString;

namespace AwsKmsPkcs11.Service
{
    public sealed class LibraryTokenManager : ITokenManager
    {
        private static readonly Pkcs11InteropFactories Factories = new Pkcs11InteropFactories();
        private static readonly string LibraryPath = Environment.OSVersion.Platform == PlatformID.Win32NT ? "libykcs11-1.dll" : "libykcs11.so";

        private readonly ILogger<TokenManager> _innerLogger;

        public LibraryTokenManager(ILogger<TokenManager> innerLogger)
        {
            _innerLogger = innerLogger ?? throw new ArgumentNullException(nameof(innerLogger));
        }

        public byte[]? Encrypt(KeyDescription key, byte[] plaintext)
            => Run(inner => inner.Encrypt(key, plaintext));

        public byte[]? TryDecrypt(KeyDescription key, byte[] ciphertext)
            => Run(inner => inner.TryDecrypt(key, ciphertext));

        public bool AreAllKeysValid(IEnumerable<KeyDescription> keys)
            => Run(inner => inner.AreAllKeysValid(keys));

        private static IPkcs11Library LoadLibrary()
        {
            var library = Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Factories, LibraryPath, AppType.SingleThreaded);
            return library ?? throw new DllNotFoundException(Invariant($"Failed to load PKCS#11 library \"{LibraryPath}\"."));
        }

        private TResult Run<TResult>(Func<ITokenManager, TResult> operation)
        {
            lock (Factories)
            {
                using var library = LoadLibrary();
                var tokenManager = new TokenManager(library, _innerLogger);
                return operation(tokenManager);
            }
        }
    }
}
