using System;

namespace AwsKmsPkcs11.Composition
{
    internal sealed class HostingOptions
    {
        private string? _listen;

        public string Listen
        {
            get => _listen ?? "";
            set => _listen = value;
        }

        public ushort MaxConcurrentConnections { get; set; }

        public bool ForceConsoleLogging { get; set; }
    }
}
