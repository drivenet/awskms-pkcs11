using System;
using System.Globalization;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

using Tmds.Systemd;

namespace AwsKmsPkcs11.Composition
{
    public static class Program
    {
        public static async Task Main(string[] args)
        {
            using var host = BuildHost(args);
            await host.RunAsync();
        }

        private static IHost BuildHost(string[] args)
            => new HostBuilder()
                .ConfigureHostConfiguration(configBuilder => configBuilder.AddCommandLine(args))
                .ConfigureWebHost(webHost => ConfigureWebHost(webHost))
                .ConfigureLogging((builderContext, loggingBuilder) => ConfigureLogging(builderContext, loggingBuilder))
#if !MINIMAL_BUILD
                .UseSystemd()
#endif
                .ConfigureAppConfiguration((builderContext, configBuilder) => ConfigureAppConfiguration(args, builderContext, configBuilder))
                .Build();

        private static IWebHostBuilder ConfigureWebHost(IWebHostBuilder webHost)
            => webHost
                .UseKestrel((builderContext, options) => ConfigureKestrel(builderContext, options))
#if !MINIMAL_BUILD
                .UseLibuv()
#endif
                .UseStartup<Startup>();

#pragma warning disable CA1801 // Review unused parameters -- requred for other build configuration
        private static void ConfigureLogging(HostBuilderContext builderContext, ILoggingBuilder loggingBuilder)
#pragma warning restore CA1801 // Review unused parameters
        {
            loggingBuilder.AddFilter(
                (category, level) => level >= LogLevel.Warning
                    || (level >= LogLevel.Information && !category.StartsWith("Microsoft.AspNetCore.", StringComparison.OrdinalIgnoreCase)));

#if !MINIMAL_BUILD
            if (Journal.IsSupported)
            {
                loggingBuilder.AddJournal(options =>
                {
                    options.SyslogIdentifier = builderContext.HostingEnvironment.ApplicationName;
                });
            }
#endif

#if !MINIMAL_BUILD
            if (builderContext.Configuration.GetValue<bool>("ForceConsoleLogging")
                 || !Journal.IsAvailable)
#endif
            {
                loggingBuilder.AddConsole(options =>
                {
                    options.IncludeScopes = true;
                    options.Format = ConsoleLoggerFormat.Systemd;
                    options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffffffzzz \""
                        + Environment.MachineName
                        + "\" \""
                        + builderContext.HostingEnvironment.ApplicationName
                        + ":\" ";
                });
            }
        }

        private static void ConfigureKestrel(WebHostBuilderContext builderContext, KestrelServerOptions options)
        {
            options.AddServerHeader = false;
            options.Limits.MaxRequestLineSize = 1024;
            options.Limits.MaxRequestBodySize = 4096;
            options.Limits.MaxRequestHeadersTotalSize = 4096;

            var kestrelSection = builderContext.Configuration.GetSection("Kestrel");
            options.Configure(kestrelSection);

            if (kestrelSection.Get<KestrelServerOptions>() is { } kestrelOptions)
            {
                options.Limits.MaxConcurrentConnections = kestrelOptions.Limits.MaxConcurrentConnections;
            }
            else
            {
                options.Limits.MaxConcurrentConnections = 10;
            }

#if !MINIMAL_BUILD
            // SD_LISTEN_FDS_START https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html
            const int SdListenFdsStart = 3;
            const string ListenFdsEnvVar = "LISTEN_FDS";

            options.UseSystemd(listenOptions =>
            {
                if (listenOptions.FileHandle == SdListenFdsStart)
                {
                    // This matches sd_listen_fds behavior that requires %LISTEN_FDS% to be present and in range [1;INT_MAX-SD_LISTEN_FDS_START]
                    if (int.TryParse(Environment.GetEnvironmentVariable(ListenFdsEnvVar), NumberStyles.None, NumberFormatInfo.InvariantInfo, out var listenFds)
                        && listenFds > 1
                        && listenFds <= int.MaxValue - SdListenFdsStart)
                    {
                        for (var handle = SdListenFdsStart + 1; handle < SdListenFdsStart + listenFds; ++handle)
                        {
                            options.ListenHandle((ulong)handle);
                        }
                    }
                }
            });
#endif
        }

        private static IConfigurationBuilder ConfigureAppConfiguration(string[] args, HostBuilderContext builderContext, IConfigurationBuilder configBuilder)
            => configBuilder
                .AddJsonFile(builderContext.Configuration.GetValue("ConfigPath", "appsettings.json"), optional: false, reloadOnChange: true)
                .AddCommandLine(args);
    }
}
