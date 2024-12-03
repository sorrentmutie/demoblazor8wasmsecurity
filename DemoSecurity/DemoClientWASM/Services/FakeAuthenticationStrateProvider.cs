using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace DemoClientWASM.Services;

public class FakeAuthenticationStateProvider: AuthenticationStateProvider
{
    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "mrfibuli"),
        }, "Fake authentication type");

        var user = new ClaimsPrincipal(identity);
         return Task.FromResult(new AuthenticationState(user));
    }
}
