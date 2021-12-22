using System;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

namespace AwsKmsPkcs11.Http;

internal static class VersionHandler
{
    private static readonly ReadOnlyMemory<byte> VersionBytes = Encoding.ASCII.GetBytes(Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "?").AsMemory();

    public static async Task Invoke(HttpContext context)
    {
        var response = context.Response;
        response.ContentLength = VersionBytes.Length;
        await response.Body.WriteAsync(VersionBytes);
    }
}
