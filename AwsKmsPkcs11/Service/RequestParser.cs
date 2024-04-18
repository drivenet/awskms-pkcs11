using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Amazon.Runtime.Internal.Auth;

using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

using static System.FormattableString;

namespace AwsKmsPkcs11.Service;

public sealed class RequestParser
{
    private const string JsonContentType = "application/x-amz-json-1.1";

    private static readonly Regex SignatureParser = new(Invariant($"^{Regex.Escape(AWS4Signer.AWS4AlgorithmTag)} {Regex.Escape(AWS4Signer.Credential)}=.+?/.+?, {Regex.Escape(AWS4Signer.SignedHeaders)}=(.+?), {Regex.Escape(AWS4Signer.Signature)}=(.+)$"), RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public async Task<ParseRequestResult> ParseRequest(HttpRequest request)
    {
        var requestEncoding = Encoding.UTF8;
        if (request.ContentType != JsonContentType)
        {
            return new InvalidRequest(StatusCodes.Status415UnsupportedMediaType, "Unsupported media type.");
        }

        var headers = request.Headers;
        if (headers["X-Amz-Date"] is not [string requestDateHeader])
        {
            return new InvalidRequest(StatusCodes.Status400BadRequest, "Missing X-Amz-Date header.");
        }

        if (!DateTime.TryParseExact(requestDateHeader, "yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var signedAt))
        {
            return new InvalidRequest(StatusCodes.Status400BadRequest, "The X-Amz-Date header value \"{Value}\" is invalid.", requestDateHeader);
        }

        if (headers["X-Amz-Target"] is not [string targetHeader])
        {
            return new InvalidRequest(StatusCodes.Status400BadRequest, "Missing X-Amz-Target header.");
        }

        if (headers[HeaderNames.Authorization] is not [string authorizationHeader])
        {
            return new InvalidRequest(StatusCodes.Status401Unauthorized, "Missing Authorization header.");
        }

        if (SignatureParser.Match(authorizationHeader) is not { Success: true } match)
        {
            return new InvalidRequest(StatusCodes.Status401Unauthorized, "The Authorization header value \"{Value}\" is invalid.", authorizationHeader);
        }

        string content;
        using (var reader = new StreamReader(request.Body, encoding: requestEncoding, detectEncodingFromByteOrderMarks: false, bufferSize: 256, leaveOpen: true))
        {
            content = await reader.ReadToEndAsync();
        }

        return new SignedRequest(request.Path, headers, match.Groups[1].Value, signedAt, match.Groups[2].Value, new KmsRequest(targetHeader, content));
    }
}
