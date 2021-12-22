using System;
using System.Threading;
using System.Threading.Tasks;

using AwsKmsPkcs11.Service;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AwsKmsPkcs11.Http;

internal sealed class SignatureHealthcheck : IHealthCheck
{
    private static readonly SignedRequest InvalidRequest =
        new(
            "/keys",
            new HeaderDictionary
            {
                ["Content-Type"] = "application/json",
                ["Host"] = "aws.amazon.com",
                ["X-Amz-Date"] = "20150830T123600Z",
                ["X-Amz-Target"] = "TrentService.Encrypt",
            },
            "content-type,host,x-amz-date,x-amz-target",
            DateTime.MinValue,
            "873f801077f296e395d761d40445c324eba5b7254ebf075831421fc03937fea3",
            new KmsRequest("TrentService.Encrypt", "{\"CiphertextBlob\":\"abcdefgh\"}"));

    private readonly SignatureVerifier _verifier;

    public SignatureHealthcheck(SignatureVerifier verifier)
    {
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
    }

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken)
    {
        if (_verifier.IsSignatureValid(InvalidRequest))
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Invalid signature is considered valid."));
        }

        return Task.FromResult(HealthCheckResult.Healthy("Invalid signature is considered invalid."));
    }
}
