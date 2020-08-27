using System;
using System.Threading.Tasks;

using AwsKmsPkcs11.Service;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using static System.FormattableString;

namespace AwsKmsPkcs11.Http
{
    internal sealed class KeysHandler
    {
        private readonly ILogger _logger;
        private readonly RequestParser _requestParser;
        private readonly SignatureVerifier _signatureVerifier;
        private readonly RequestProcessor _requestProcessor;

        public KeysHandler(ILogger<KeysHandler> logger, RequestParser requestParser, SignatureVerifier signatureVerifier, RequestProcessor requestProcessor)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _requestParser = requestParser ?? throw new ArgumentNullException(nameof(requestParser));
            _signatureVerifier = signatureVerifier ?? throw new ArgumentNullException(nameof(signatureVerifier));
            _requestProcessor = requestProcessor ?? throw new ArgumentNullException(nameof(requestProcessor));
        }

        public async Task Invoke(HttpContext httpContext)
        {
            await HandleRequest(httpContext.Request, httpContext.Response);
        }

        private async Task HandleRequest(HttpRequest request, HttpResponse response)
        {
            var result = await _requestParser.ParseRequest(request);
            switch (result)
            {
                case SignedRequest signedRequest:
                    await HandleKmsRequest(signedRequest, response);
                    break;

                case InvalidRequest invalidRequest:
                    response.StatusCode = invalidRequest.StatusCode;
                    _logger.LogError(EventIds.InvalidRequest, invalidRequest.Message, invalidRequest.Args);
                    break;

                default:
                    throw new InvalidOperationException(Invariant($"Unexpected parse result {result}."));
            }
        }

        private async Task HandleKmsRequest(SignedRequest request, HttpResponse response)
        {
            if (!_signatureVerifier.IsSignatureValid(request))
            {
                response.StatusCode = StatusCodes.Status401Unauthorized;
                _logger.LogError(EventIds.InvalidRequest, "Computed request signature does not match provided \"{Signature}\".", request.Signature);
                return;
            }

            var result = _requestProcessor.ProcessRequest(request.Request);
            switch (result)
            {
                case KmsResponse kmsResponse:
                    const string JsonContentType = "application/x-amz-json-1.1";
                    response.ContentType = JsonContentType;
                    await response.WriteAsync(kmsResponse.Content);
                    break;

                case InvalidKmsRequest invalidRequest:
                    response.StatusCode = StatusCodes.Status400BadRequest;
                    _logger.LogError(EventIds.InvalidKmsRequest, invalidRequest.Message, invalidRequest.Args);
                    break;

                default:
                    throw new InvalidOperationException(Invariant($"Unexpected KMS result {result}."));
            }
        }

        private static class EventIds
        {
            public static readonly EventId InvalidRequest = new EventId(1, nameof(InvalidRequest));
            public static readonly EventId InvalidKmsRequest = new EventId(2, nameof(InvalidKmsRequest));
        }
    }
}
