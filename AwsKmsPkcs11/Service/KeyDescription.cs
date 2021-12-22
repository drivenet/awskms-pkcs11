using System;

namespace AwsKmsPkcs11.Service;

public sealed class KeyDescription
{
    public KeyDescription(string tokenSerialNumber, string tokenPin, byte keyId)
    {
        if (string.IsNullOrEmpty(tokenSerialNumber))
        {
            throw new ArgumentException("Token serial number cannot be null or empty.", nameof(tokenSerialNumber));
        }

        if (string.IsNullOrEmpty(tokenPin))
        {
            throw new ArgumentException("Token PIN cannot be null or empty.", nameof(tokenPin));
        }

        TokenSerialNumber = tokenSerialNumber;
        TokenPin = tokenPin;
        KeyId = keyId;
    }

    public string TokenSerialNumber { get; }

    public string TokenPin { get; }

    public byte KeyId { get; }
}
