using System;

namespace AwsKmsPkcs11.Service
{
    public sealed class InvalidKmsRequest : ProcessRequestResult
    {
        public InvalidKmsRequest(string message, params string[] args)
        {
            Message = message ?? throw new ArgumentNullException(nameof(message));
            Args = args;
        }

        public string Message { get; }

#pragma warning disable CA1819 // Properties should not return arrays -- required to match logging facilities
        public string[] Args { get; }
#pragma warning restore CA1819 // Properties should not return arrays
    }
}
