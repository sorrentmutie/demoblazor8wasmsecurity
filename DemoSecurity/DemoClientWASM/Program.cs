using Blazored.LocalStorage;
using DemoClientWASM;
using DemoClientWASM.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
// builder.Services.AddCascadingAuthenticationState();
//builder.Services.AddScoped<AuthenticationStateProvider, FakeAuthenticationStateProvider>();

builder.Services.AddBlazoredLocalStorage();
builder.Services.AddScoped<AppAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(
    provider => provider.GetRequiredService<AppAuthenticationStateProvider>());


await builder.Build().RunAsync();
