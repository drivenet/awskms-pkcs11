using System;
using System.Text;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AwsKmsPkcs11.Service
{
    public sealed class KeyManager
    {
        private readonly TokenManager _tokenManager;
        private readonly IOptionsMonitor<KeyOptions> _options;
        private readonly ILogger _logger;

        public KeyManager(TokenManager tokenManager, IOptionsMonitor<KeyOptions> options, ILogger<KeyManager> logger)
        {
            _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public bool AreAllKeysValid()
        {
            var keyDescriptons = _options.CurrentValue.KeyDescriptions;
            if (keyDescriptons.Count == 0)
            {
                return false;
            }

            return _tokenManager.AreAllKeysValid(keyDescriptons.Values);
        }

        public byte[]? Encrypt(string keyId, byte[] plaintext)
        {
            if (!_options.CurrentValue.KeyDescriptions.TryGetValue(keyId, out var key))
            {
                return null;
            }

            var ciphertext = _tokenManager.Encrypt(key, plaintext);
            if (ciphertext is null)
            {
                return null;
            }

            var keyIdLength = checked((byte)keyId.Length);
            var result = new byte[1 + keyIdLength + ciphertext.Length];
            result[0] = keyIdLength;
            Encoding.ASCII.GetBytes(keyId, 0, keyIdLength, result, 1);
            ciphertext.CopyTo(result, 1 + keyIdLength);
            return result;
        }

        public byte[]? Decrypt(byte[] ciphertext)
        {
            var length = ciphertext.Length;
            if (length < 3)
            {
                return null;
            }

            var keyIdLength = ciphertext[0];
            var payloadLength = length - keyIdLength - 1;
            if (payloadLength < 1)
            {
                return null;
            }

            var keyId = Encoding.ASCII.GetString(ciphertext, 1, keyIdLength);
            if (!_options.CurrentValue.KeyDescriptions.TryGetValue(keyId, out var key))
            {
                _logger.LogError(EventIds.DecryptionKeyNotFound, "Decryption key with id \"{KeyId}\" was not found.", keyId);
                return null;
            }

            var payload = new byte[payloadLength];
            Buffer.BlockCopy(ciphertext, keyIdLength + 1, payload, 0, payloadLength);
            return _tokenManager.TryDecrypt(key, payload);
        }

        private static class EventIds
        {
            public static readonly EventId DecryptionKeyNotFound = new EventId(1, nameof(DecryptionKeyNotFound));
        }
    }
}
