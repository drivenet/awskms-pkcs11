using System.Text.RegularExpressions;

namespace AwsKmsPkcs11.Service;

internal static partial class KeyIdValidator
{
    private static readonly Regex Template = CreateTemplate();

    public static bool IsKeyValid(string keyId) => Template.IsMatch(keyId);

    [GeneratedRegex("^[A-Za-z0-9_.-]{1,255}$", RegexOptions.Compiled | RegexOptions.CultureInvariant)]
    private static partial Regex CreateTemplate();
}
