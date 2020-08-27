namespace AwsKmsPkcs11.Service
{
    public sealed class TokenOptions
    {
        private string? _tokenPin;

        public string? TokenPin
        {
            get => _tokenPin ?? "123456";
            set
            {
                var tokenPin = value;
                if (tokenPin?.Length == 0)
                {
                    tokenPin = null;
                }

                _tokenPin = tokenPin;
            }
        }
    }
}
