using System;
using System.Text.Json;

namespace AwsKmsPkcs11.Service
{
    public sealed partial class RequestProcessor
    {
        private readonly KeyManager _keyManager;

        public RequestProcessor(KeyManager keyManager)
        {
            _keyManager = keyManager ?? throw new ArgumentNullException(nameof(keyManager));
        }

        public ProcessRequestResult ProcessRequest(KmsRequest request)
            => request.Target switch
            {
                "TrentService.DescribeKey" => DescribeKey(request.Content),
                "TrentService.Encrypt" => Encrypt(request.Content),
                "TrentService.Decrypt" => Decrypt(request.Content),
                _ => new InvalidKmsRequest("Unknown target \"{Target}\".", request.Target),
            };

        private ProcessRequestResult DescribeKey(string content)
        {
            var requestObject = JsonSerializer.Deserialize<DescribeKeyRequest>(content);
            if (!(requestObject.KeyId is { } keyId))
            {
                return new InvalidKmsRequest("Missing KeyId for DescribeKey.");
            }

            if (!_keyManager.IsValidKeyId(requestObject.KeyId))
            {
                return new InvalidKmsRequest("Unknown key {KeyId} for DescribeKey.", requestObject.KeyId);
            }

            return new KmsResponse("{\"KeyMetadata\":{\"KeyId\":\"" + requestObject.KeyId + "\"}}");
        }

        private ProcessRequestResult Encrypt(string content)
        {
            var requestObject = JsonSerializer.Deserialize<EncryptKeyRequest>(content);
            if (!(requestObject.KeyId is { } keyId))
            {
                return new InvalidKmsRequest("Missing KeyId for EncryptKey.");
            }

            if (!(requestObject.Plaintext is { } plaintext))
            {
                return new InvalidKmsRequest("Missing Plaintext for EncryptKey.");
            }

            byte[] plaintextBytes;
            try
            {
                plaintextBytes = Convert.FromBase64String(plaintext);
            }
            catch (FormatException)
            {
                return new InvalidKmsRequest("Invalid EncryptKeyRequest.Plaintext \"{Plaintext}\".", plaintext);
            }

            var ciphertextBytes = _keyManager.Encrypt(keyId, plaintextBytes);
            if (ciphertextBytes is null)
            {
                return new InvalidKmsRequest("Invalid encryption for key {KeyId}.", keyId);
            }

            var ciphertext = Convert.ToBase64String(ciphertextBytes);
            return new KmsResponse("{\"CiphertextBlob\":\"" + ciphertext + "\"}");
        }

        private ProcessRequestResult Decrypt(string content)
        {
            var requestObject = JsonSerializer.Deserialize<DecryptKeyRequest>(content);
            if (!(requestObject.CiphertextBlob is { } blob))
            {
                return new InvalidKmsRequest("Missing CiphertextBlob for DecryptKey.");
            }

            byte[] ciphertext;
            try
            {
                ciphertext = Convert.FromBase64String(blob);
            }
            catch (FormatException)
            {
                return new InvalidKmsRequest("Invalid CiphertextBlob \"{CiphertextBlob}\" for DecryptKey.", blob);
            }

            var plaintextBytes = _keyManager.Decrypt(ciphertext);
            if (plaintextBytes is null)
            {
                return new InvalidKmsRequest("Invalid decryption.");
            }

            var plaintext = Convert.ToBase64String(plaintextBytes);
            return new KmsResponse("{\"Plaintext\":\"" + plaintext + "\"}");
        }
    }
}
