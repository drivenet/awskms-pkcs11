﻿using System;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using Tmds.Systemd;

namespace AwsKmsPkcs11.Composition;

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
            .ConfigureLogging(ConfigureLogging)
#if !MINIMAL_BUILD
                .UseSystemd()
#endif
                .ConfigureAppConfiguration((builderContext, configBuilder) => ConfigureAppConfiguration(args, builderContext, configBuilder))
            .Build();

    private static IWebHostBuilder ConfigureWebHost(IWebHostBuilder webHost)
        => webHost
            .UseKestrel(ConfigureKestrel)
            .UseStartup<Startup>();

#if MINIMAL_BUILD
#pragma warning disable CA1801 // Review unused parameters -- required for other build configuration
#endif
    private static void ConfigureLogging(HostBuilderContext builderContext, ILoggingBuilder loggingBuilder)
#if MINIMAL_BUILD
#pragma warning restore CA1801 // Review unused parameters
#endif
    {
        loggingBuilder.AddFilter(
            (category, level) => level >= LogLevel.Warning
                || (level >= LogLevel.Information && category?.StartsWith("Microsoft.AspNetCore.", StringComparison.OrdinalIgnoreCase) != true));

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
            loggingBuilder.AddSystemdConsole(options =>
            {
                options.IncludeScopes = true;
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
        options.UseSystemd();
#endif
    }

    private static IConfigurationBuilder ConfigureAppConfiguration(string[] args, HostBuilderContext builderContext, IConfigurationBuilder configBuilder)
        => configBuilder
            .AddJsonFile(builderContext.Configuration.GetValue<string>("ConfigPath") ?? "appsettings.json", optional: false, reloadOnChange: true)
            .AddCommandLine(args);
}
