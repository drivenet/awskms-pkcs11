namespace AwsKmsPkcs11.Composition
{
    internal sealed class CommandLineOptions
    {
        private string? _config;

        public string Config
        {
            get => string.IsNullOrWhiteSpace(_config) ? "appsettings.json" : _config;
            set => _config = value;
        }
    }
}
