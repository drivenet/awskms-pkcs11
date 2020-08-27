using System;

namespace AwsKmsPkcs11.Service
{
    public sealed class KmsRequest
    {
        public KmsRequest(string target, string content)
        {
            Target = target ?? throw new ArgumentNullException(nameof(target));
            Content = content ?? throw new ArgumentNullException(nameof(content));
        }

        public string Target { get; }

        public string Content { get; }
    }
}
