using System;

namespace AwsKmsPkcs11.Service
{
    public sealed class KeyDescription
    {
        public KeyDescription(string tokenSerialNumber, byte keyId)
        {
            TokenSerialNumber = tokenSerialNumber ?? throw new ArgumentNullException(nameof(tokenSerialNumber));
            KeyId = keyId;
        }

        public string TokenSerialNumber { get; }

        public byte KeyId { get; }
    }
}
