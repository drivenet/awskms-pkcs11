using System;
using System.Text;

using Amazon.Runtime.Internal.Auth;
using Amazon.Util;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AwsKmsPkcs11.Service;

public sealed class SignatureVerifier
{
    private readonly IOptionsMonitor<SignatureOptions> _options;

    public SignatureVerifier(IOptionsMonitor<SignatureOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public bool IsSignatureValid(SignedRequest request)
    {
        var options = _options.CurrentValue;
        if (options.Credentials is not { } credentials)
        {
            return false;
        }

        var canonicalRequest = CreateCanonicalRequest(request.Path, request.Headers, request.SignedHeaders, request.Request.Content);
        const string ServiceName = "kms";
        var computedSignature = AWS4Signer.ComputeSignature(credentials, options.Region, request.SignedAt, ServiceName, request.SignedHeaders, canonicalRequest).Signature;
        return request.Signature == computedSignature;
    }

    private static string CreateCanonicalRequest(string path, IHeaderDictionary headers, string signedHeaders, string content)
    {
        var builder = new StringBuilder();
        builder.Append("POST\n");
        builder.Append(path);
        builder.Append("\n\n");
        foreach (var header in signedHeaders.Split(';'))
        {
            if (!headers.TryGetValue(header, out var headerValue))
            {
                continue;
            }

            builder.Append(header);
            builder.Append(':');
            var isFirst = true;
            foreach (var value in headerValue)
            {
                if (isFirst)
                {
                    isFirst = false;
                }
                else
                {
                    builder.Append(',');
                }

                builder.Append(value.Trim());
            }

            builder.Append('\n');
        }

        builder.Append('\n');
        builder.Append(signedHeaders);
        builder.Append('\n');
        builder.Append(AWSSDKUtils.ToHex(AWS4Signer.ComputeHash(content), true));
        return builder.ToString();
    }
}
