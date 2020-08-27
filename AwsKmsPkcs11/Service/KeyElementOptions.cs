namespace AwsKmsPkcs11.Service
{
    public class KeyElementOptions
    {
        private byte _id;

        public string? Serial { get; set; }

        public byte Id
        {
            get => _id == 0 ? (byte)1 : _id;
            set => _id = value;
        }
    }
}
