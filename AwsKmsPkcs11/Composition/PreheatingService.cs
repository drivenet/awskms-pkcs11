using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Hosting;

namespace AwsKmsPkcs11.Composition
{
    internal sealed class PreheatingService : IHostedService
    {
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await Task.Run(() =>
            {
            });
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
