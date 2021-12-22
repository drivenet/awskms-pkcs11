namespace AwsKmsPkcs11.Service;

public sealed partial class RequestProcessor
{
    private sealed class DescribeKeyRequest
    {
        public string? KeyId { get; set; }
    }

    private sealed class EncryptKeyRequest
    {
        public string? KeyId { get; set; }

        public string? Plaintext { get; set; }
    }

    private sealed class DecryptKeyRequest
    {
        public string? CiphertextBlob { get; set; }
    }
}
