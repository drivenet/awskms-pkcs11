using System;

namespace AwsKmsPkcs11.Service
{
    public sealed class InvalidRequest : ParseRequestResult
    {
        public InvalidRequest(int statusCode, string message, params string[] args)
        {
            StatusCode = statusCode;
            Message = message ?? throw new ArgumentNullException(nameof(message));
            Args = args;
        }

        public int StatusCode { get; }

        public string Message { get; }

#pragma warning disable CA1819 // Properties should not return arrays -- required to match logging facilities
        public string[] Args { get; }
#pragma warning restore CA1819 // Properties should not return arrays
    }
}
