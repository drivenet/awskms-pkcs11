using System;
using System.Collections.Generic;
using System.Text;

namespace AwsKmsPkcs11.Service
{
    public sealed class KeyManager
    {
        private readonly IReadOnlyDictionary<string, KeyDescription> _keys = new Dictionary<string, KeyDescription>
        {
            //validate ascii and shorter than 255
            ["19ec80b0-dfdd-4d97-8164-c6examplekey"] = new KeyDescription("7837571", 1),
        };

        private readonly TokenManager _tokenManager;

        public KeyManager(TokenManager tokenManager)
        {
            _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
        }

        public bool IsValidKeyId(string keyId) => _keys.ContainsKey(keyId);

        public byte[]? Encrypt(string keyId, byte[] plaintext)
        {
            if (!_keys.TryGetValue(keyId, out var key))
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
            if (!_keys.TryGetValue(keyId, out var key))
            {
                return null;
            }

            var payload = new byte[payloadLength];
            Buffer.BlockCopy(ciphertext, keyIdLength + 1, payload, 0, payloadLength);
            return _tokenManager.TryDecrypt(key, payload);
        }
    }
}
