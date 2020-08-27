namespace AwsKmsPkcs11.Service
{
    public class KeyElementOptions
    {
        private byte _id;
        private string? _pin;

        public string? Serial { get; set; }

        public byte Id
        {
            get => _id == 0 ? (byte)1 : _id;
            set => _id = value;
        }

        public string Pin
        {
            get => _pin ?? "123456";
            set
            {
                var pin = value;
                if (pin?.Length == 0)
                {
                    pin = null;
                }

                _pin = pin;
            }
        }
    }
}
