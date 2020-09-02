using System;

using AwsKmsPkcs11.Http;
using AwsKmsPkcs11.Service;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AwsKmsPkcs11.Composition
{
    internal sealed class Startup
    {
        private readonly IConfiguration _configuration;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public void ConfigureServices(IServiceCollection services)
        {
            if (services is null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            ConfigureApplication(services);
            ConfigureAspNet(services);
        }

#pragma warning disable CA1822 // Mark members as static -- future-proofing
        public void Configure(IApplicationBuilder app)
#pragma warning restore CA1822 // Mark members as static
        {
            if (app is null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            app.UseRouting();

            app.UseEndpoints(routes =>
            {
                routes.MapGet("/version", VersionHandler.Invoke);
                routes.MapHealthChecks("/healthcheck");
                routes.MapPost("/keys", app.ApplicationServices.GetRequiredService<KeysHandler>().Invoke);
            });
        }

        private static void ConfigureAspNet(IServiceCollection services)
        {
            services.AddRouting();
            services.AddHealthChecks()
                .AddCheck<KeysHealthCheck>("keys");
        }

        private void ConfigureApplication(IServiceCollection services)
        {
            services.Configure<SignatureOptions>(_configuration);
            services.Configure<KeyOptions>(_configuration);

            services.AddSingleton<KeysHandler>();
            services.AddSingleton<RequestParser>();
            services.AddSingleton<SignatureVerifier>();
            services.AddSingleton<RequestProcessor>();
            services.AddSingleton<KeyManager>();
            services.AddSingleton<TokenManager>();
        }
    }
}
