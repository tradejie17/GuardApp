using Guard.Core;
using Guard.Service.Admin;
using Guard.Service.Configuration;
using Guard.Service.Enforcement;
using Guard.Service.Logging;
using Guard.Service.Messaging;
using Guard.Service.Security;

GuardPaths.EnsureDirectories();

var builder = Host.CreateApplicationBuilder(args);

// Runs as a Windows service when the Service Control Manager starts it, and as a plain console
// application when started by hand for debugging. AddWindowsService detects which.
builder.Services.AddWindowsService(options => options.ServiceName = GuardPaths.ServiceName);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddProvider(new FileLoggerProvider(GuardPaths.ServiceLog));
builder.Logging.SetMinimumLevel(LogLevel.Information);

builder.Services.AddSingleton<ConfigStore>();
builder.Services.AddSingleton<StateStore>();
builder.Services.AddSingleton<SecretsStore>();
builder.Services.AddSingleton<GuardLogger>();
builder.Services.AddSingleton<EnforcementManager>();
builder.Services.AddSingleton<AdminCommandHandler>();
builder.Services.AddSingleton<SessionRegistry>();
builder.Services.AddHostedService<PipeServerWorker>();

var host = builder.Build();
await host.RunAsync();
