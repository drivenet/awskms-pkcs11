namespace AwsKmsPkcs11.Service;

public class KeyElementOptions
{
    // Default PIN for YubiKey and some other smart cards
    private const string DefaultPIN = "123456";

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
        get => _pin ?? DefaultPIN;
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
