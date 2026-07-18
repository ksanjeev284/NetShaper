using System.Runtime.Versioning;
using NetShaper.Service;

[assembly: SupportedOSPlatform("windows")]

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "NetShaper";
});
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
