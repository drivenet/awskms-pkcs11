using System.Threading;

using Amazon;
using Amazon.Runtime;

namespace AwsKmsPkcs11.Service
{
    public sealed class SignatureOptions
    {
        private string? _accessKey;
        private string? _secretKey;
        private string? _region;

        private ImmutableCredentials? _credentials;

        public string? AccessKey
        {
            get => _accessKey;
            set
            {
                _accessKey = value;
                Interlocked.Exchange(ref _credentials, null);
            }
        }

        public string? SecretKey
        {
            get => _secretKey;
            set
            {
                _secretKey = value;
                Interlocked.Exchange(ref _credentials, null);
            }
        }

        public string Region
        {
            get => _region ?? RegionEndpoint.USEast1.SystemName;
            set
            {
                var region = value?.Trim();
                if (region?.Length == 0)
                {
                    region = null;
                }

                _region = region;
            }
        }

        internal ImmutableCredentials? Credentials
        {
            get
            {
                var credentials = _credentials;
                if (credentials is null)
                {
                    if (_accessKey is { } accessKey
                        && _secretKey is { } secretKey)
                    {
                        _credentials = credentials = new ImmutableCredentials(accessKey, secretKey, null);
                    }
                }

                return credentials;
            }
        }
    }
}
