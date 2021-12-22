using System.Collections.Generic;

namespace AwsKmsPkcs11.Service;

public interface ITokenManager
{
    bool AreAllKeysValid(IEnumerable<KeyDescription> keys);

    byte[]? Encrypt(KeyDescription key, byte[] plaintext);

    byte[]? TryDecrypt(KeyDescription key, byte[] ciphertext);
}
