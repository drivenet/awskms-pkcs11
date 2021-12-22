using System;

namespace AwsKmsPkcs11.Service;

public sealed class KmsResponse : ProcessRequestResult
{
    public KmsResponse(string content)
    {
        Content = content ?? throw new ArgumentNullException(nameof(content));
    }

    public string Content { get; }
}
