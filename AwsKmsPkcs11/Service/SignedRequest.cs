using System;

using Microsoft.AspNetCore.Http;

namespace AwsKmsPkcs11.Service;

public sealed class SignedRequest : ParseRequestResult
{
    public SignedRequest(string path, IHeaderDictionary headers, string signedHeaders, DateTime signedAt, string signature, KmsRequest request)
    {
        Path = path ?? throw new ArgumentNullException(nameof(path));
        Headers = headers ?? throw new ArgumentNullException(nameof(headers));
        SignedHeaders = signedHeaders ?? throw new ArgumentNullException(nameof(signedHeaders));
        SignedAt = signedAt;
        Signature = signature ?? throw new ArgumentNullException(nameof(signature));
        Request = request ?? throw new ArgumentNullException(nameof(request));
    }

    public string Path { get; }

    public IHeaderDictionary Headers { get; }

    public string SignedHeaders { get; }

    public DateTime SignedAt { get; }

    public string Signature { get; }

    public KmsRequest Request { get; }
}
