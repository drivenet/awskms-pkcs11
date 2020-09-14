using System;
using System.Collections.Generic;

namespace AwsKmsPkcs11.Service
{
    public sealed partial class LibraryTokenManager
    {
        private sealed class DisposableTokenManager : ITokenManager, IDisposable
        {
            private readonly ITokenManager _inner;
            private readonly IDisposable _disposable;

            public DisposableTokenManager(ITokenManager inner, IDisposable disposable)
            {
                _inner = inner ?? throw new ArgumentNullException(nameof(inner));
                _disposable = disposable ?? throw new ArgumentNullException(nameof(disposable));
            }

            public bool AreAllKeysValid(IEnumerable<KeyDescription> keys) => _inner.AreAllKeysValid(keys);

            public byte[]? Encrypt(KeyDescription key, byte[] plaintext) => _inner.Encrypt(key, plaintext);

            public byte[]? TryDecrypt(KeyDescription key, byte[] ciphertext) => _inner.TryDecrypt(key, ciphertext);

            public void Dispose() => _disposable.Dispose();
        }
    }
}
