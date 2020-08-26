using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Amazon.Runtime;
using Amazon.Runtime.Internal.Auth;
using Amazon.Util;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

using static System.FormattableString;

namespace AwsKmsPkcs11.Http
{
    internal sealed class KeysHandler
    {
        private static readonly Regex SignatureParser = new Regex(Invariant($"^{Regex.Escape(AWS4Signer.AWS4AlgorithmTag)} {Regex.Escape(AWS4Signer.Credential)}=.+?/.+?, {Regex.Escape(AWS4Signer.SignedHeaders)}=(.+?), {Regex.Escape(AWS4Signer.Signature)}=(.+)$"), RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private readonly ILogger _logger;
        //config this
        private readonly ImmutableCredentials _credentials = new ImmutableCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", null);
        private readonly string _region = "us-east-1";

        public KeysHandler(ILogger<KeysHandler> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task Invoke(HttpContext httpContext)
        {
            var request = httpContext.Request;
            var response = httpContext.Response;
            var requestEncoding = Encoding.UTF8;
            const string JsonContentType = "application/x-amz-json-1.1";
            if (request.ContentType != JsonContentType)
            {
                response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
                return;
            }

            var headers = request.Headers;
            if (!(headers["X-Amz-Date"] is { Count: 1 } requestDateHeader))
            {
                _logger.LogWarning(EventIds.InvalidRequest, "Missing X-Amz-Date header.");
                response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            if (!DateTime.TryParseExact(requestDateHeader[0], "yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var signedAt))
            {
                _logger.LogError(EventIds.InvalidRequest, "The X-Amz-Date header value \"{Value}\" is invalid.", requestDateHeader[0]);
                response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            if (!(headers["X-Amz-Target"] is { Count: 1 } targetHeader))
            {
                _logger.LogError(EventIds.InvalidRequest, "Missing X-Amz-Target header.");
                response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            if (!(headers[HeaderNames.Authorization] is { Count: 1 } authorizationHeader))
            {
                _logger.LogWarning(EventIds.UnauthorizedRequest, "Missing Authorization header.");
                response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            if (!(SignatureParser.Match(authorizationHeader[0]) is { Success: true } match))
            {
                _logger.LogError(EventIds.UnauthorizedRequest, "The Authorization header value \"{Value}\" is invalid.", authorizationHeader[0]);
                response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            var signedHeaders = match.Groups[1].Value;
            var providedSignature = match.Groups[2].Value;

            var url = request.HttpContext.Features.Get<IHttpRequestFeature>().RawTarget;
            string content;
            using (var reader = new StreamReader(request.Body, encoding: requestEncoding, detectEncodingFromByteOrderMarks: false, bufferSize: 256, leaveOpen: true))
            {
                content = await reader.ReadToEndAsync();
            }

            var canonicalRequest = CreateCanonicalRequest(url, headers, signedHeaders, content);
            const string ServiceName = "kms";
            var computedSignature = AWS4Signer.ComputeSignature(_credentials, _region, signedAt, ServiceName, signedHeaders, canonicalRequest).Signature;
            if (computedSignature != providedSignature)
            {
                _logger.LogError(EventIds.UnauthorizedRequest, "Computed request signature \"{ComputedSignature}\" does not match provided \"{ProvidedSignature}\".", computedSignature, providedSignature);
                response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            switch (targetHeader[0])
            {
                case "TrentService.DescribeKey":
                    {
                        var requestObject = JsonSerializer.Deserialize<DescribeKeyRequest>(content);
                        if (requestObject.KeyId is null)
                        {
                            _logger.LogError(EventIds.InvalidRequest, "Missing DescribeKeyRequest.KeyId.");
                            response.StatusCode = StatusCodes.Status400BadRequest;
                            return;
                        }

                        if (!IsValidKeyId(requestObject.KeyId))
                        {
                            _logger.LogError(EventIds.InvalidRequest, "Unknown key {KeyId}.", requestObject.KeyId);
                            response.StatusCode = StatusCodes.Status404NotFound;
                            return;
                        }

                        var responseContent = "{\"KeyMetadata\":{\"KeyId\":\"" + requestObject.KeyId + "\"}}";
                        response.ContentType = JsonContentType;
                        await response.WriteAsync(responseContent);
                    }

                    break;

                case "TrentService.Encrypt":
                    {
                        var requestObject = JsonSerializer.Deserialize<EncryptKeyRequest>(content);
                        if (requestObject.KeyId is null)
                        {
                            _logger.LogError(EventIds.InvalidRequest, "Missing EncryptKeyRequest.KeyId.");
                            response.StatusCode = StatusCodes.Status400BadRequest;
                            return;
                        }

                        if (requestObject.Plaintext is null)
                        {
                            _logger.LogError(EventIds.InvalidRequest, "Missing EncryptKeyRequest.Plaintext.");
                            response.StatusCode = StatusCodes.Status400BadRequest;
                            return;
                        }

                        byte[] plaintext;
                        try
                        {
                            plaintext = Convert.FromBase64String(requestObject.Plaintext);
                        }
                        catch (FormatException exception)
                        {
                            _logger.LogError(EventIds.InvalidRequest, exception, "Invalid EncryptKeyRequest.Plaintext \"{Plaintext}\".", requestObject.Plaintext);
                            response.StatusCode = StatusCodes.Status400BadRequest;
                            return;
                        }

                        var ciphertext = Encrypt(requestObject.KeyId, plaintext);
                        var responseContent = "{\"KeyId\":\"" + requestObject.KeyId + "\", \"CiphertextBlob\":\"" + Convert.ToBase64String(ciphertext) + "\"}";
                        response.ContentType = JsonContentType;
                        await response.WriteAsync(responseContent);
                    }

                    break;

                case "TrentService.Decrypt":
                    {
                        var requestObject = JsonSerializer.Deserialize<DecryptKeyRequest>(content);
                        if (requestObject.CiphertextBlob is null)
                        {
                            _logger.LogError(EventIds.InvalidRequest, "Missing DecryptKeyRequest.CiphertextBlob.");
                            response.StatusCode = StatusCodes.Status400BadRequest;
                            return;
                        }

                        byte[] ciphertext;
                        try
                        {
                            ciphertext = Convert.FromBase64String(requestObject.CiphertextBlob);
                        }
                        catch (FormatException exception)
                        {
                            _logger.LogError(EventIds.InvalidRequest, exception, "Invalid DecryptKeyRequest.CiphertextBlob \"{CiphertextBlob}\".", requestObject.CiphertextBlob);
                            response.StatusCode = StatusCodes.Status400BadRequest;
                            return;
                        }

                        var plaintext = Decrypt(ciphertext);
                        var responseContent = "{\"Plaintext\":\"" + Convert.ToBase64String(plaintext) + "\"}";
                        response.ContentType = JsonContentType;
                        await response.WriteAsync(responseContent);
                    }

                    break;

                default:
                    _logger.LogError(EventIds.UnknownTarget, "Unknown target \"{Target}\".", targetHeader[0]);
                    response.StatusCode = StatusCodes.Status501NotImplemented;
                    return;
            }
        }

        private static string CreateCanonicalRequest(string url, IHeaderDictionary headers, string signedHeaders, string content)
        {
            var builder = new StringBuilder();
            builder.Append("POST\n");
            builder.Append(url);
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
            var canonicalRequest = builder.ToString();
            return canonicalRequest;
        }

        private bool IsValidKeyId(string keyId) => true;

        private byte[] Encrypt(string keyId, byte[] plaintext)
        {
            return plaintext;
        }

        private byte[] Decrypt(byte[] ciphertext)
        {
            return ciphertext;
        }

        private static class EventIds
        {
            public static readonly EventId InvalidRequest = new EventId(1, nameof(InvalidRequest));
            public static readonly EventId UnauthorizedRequest = new EventId(2, nameof(UnauthorizedRequest));
            public static readonly EventId UnknownTarget = new EventId(3, nameof(UnknownTarget));
        }

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
}
