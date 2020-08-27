namespace AwsKmsPkcs11.Service
{
    public sealed class KeyManager
    {
        public bool IsValidKeyId(string keyId) => true;

        public byte[] Encrypt(string keyId, byte[] plaintext)
        {
            return plaintext;
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            return ciphertext;
        }
    }
}
