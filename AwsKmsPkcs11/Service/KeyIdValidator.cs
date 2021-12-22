using System.Text.RegularExpressions;

namespace AwsKmsPkcs11.Service;

internal static class KeyIdValidator
{
    private static readonly Regex Template = new("^[A-Za-z0-9_.-]{1,255}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static bool IsKeyValid(string keyId) => Template.IsMatch(keyId);
}
