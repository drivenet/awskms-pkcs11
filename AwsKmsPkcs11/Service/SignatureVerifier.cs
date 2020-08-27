using System;
using System.Text;

using Amazon.Runtime;
using Amazon.Runtime.Internal.Auth;
using Amazon.Util;

using Microsoft.AspNetCore.Http;

namespace AwsKmsPkcs11.Service
{
    public sealed class SignatureVerifier
    {
        private readonly ImmutableCredentials _credentials = new ImmutableCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", null);
        private readonly string _region = "us-east-1";

        public bool IsSignatureValid(SignedRequest request)
        {
            var computedSignature = ComputeSignature(request.Path, request.Headers, request.SignedHeaders, request.SignedAt, request.Request.Content);
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

        private string ComputeSignature(string url, IHeaderDictionary headers, string signedHeaders, DateTime signedAt, string content)
        {
            var canonicalRequest = CreateCanonicalRequest(url, headers, signedHeaders, content);
            const string ServiceName = "kms";
            return AWS4Signer.ComputeSignature(_credentials, _region, signedAt, ServiceName, signedHeaders, canonicalRequest).Signature;
        }
    }
}
