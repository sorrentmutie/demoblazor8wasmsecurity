using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace DemoClientWASM.Services;






public class AppAuthenticationStateProvider: AuthenticationStateProvider
{
    private readonly ILocalStorageService localStorageService;
    private JwtSecurityTokenHandler JwtSecurityTokenHandler = new();

    public AppAuthenticationStateProvider(ILocalStorageService localStorageService)
    {
        this.localStorageService = localStorageService;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            var savedToken = await localStorageService.GetItemAsync<string>("bearerToken");
            if (string.IsNullOrWhiteSpace(savedToken))
            {
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            var jwtSecurityToken = JwtSecurityTokenHandler.ReadJwtToken(savedToken);
            DateTime tokenExpiry = jwtSecurityToken.ValidTo;

            if (tokenExpiry < DateTime.UtcNow)
            {
                await localStorageService.RemoveItemAsync("bearerToken");
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            var claims = jwtSecurityToken.Claims.ToList();

            var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));  
            return new AuthenticationState(user);

        }
        catch 
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }


    }


    public async Task SignIn()
    {
        var savedToken = await localStorageService.GetItemAsync<string>("bearerToken");

        var claims = JwtSecurityTokenHandler.ReadJwtToken(savedToken).Claims.ToList();
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));
        Task<AuthenticationState> authState = Task.FromResult(new AuthenticationState(user));
        NotifyAuthenticationStateChanged(authState);
    }

    public async Task SignOut()
    {
       var nobody = new ClaimsPrincipal(new ClaimsIdentity());  
       Task<AuthenticationState> authState = Task.FromResult(new AuthenticationState(nobody));

        await localStorageService.SetItemAsStringAsync("bearerToken", "");
        NotifyAuthenticationStateChanged(authState);
    }


}
