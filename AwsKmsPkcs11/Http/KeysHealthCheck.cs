using System;
using System.Threading;
using System.Threading.Tasks;

using AwsKmsPkcs11.Service;

using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AwsKmsPkcs11.Http
{
    internal sealed class KeysHealthCheck : IHealthCheck
    {
        private readonly KeyManager _keyManager;

        public KeysHealthCheck(KeyManager keyManager)
        {
            _keyManager = keyManager ?? throw new ArgumentNullException(nameof(keyManager));
        }

        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken)
        {
            if (!_keyManager.AreAllKeysValid())
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("KMS keys are missing or invalid."));
            }

            return Task.FromResult(HealthCheckResult.Healthy("KMS keys are valid."));
        }
    }
}
