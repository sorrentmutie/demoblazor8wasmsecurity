using DemoSecurity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DemoSecurity.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;
        private readonly IConfiguration configuration;

        public AccountsController(SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.configuration = configuration;
        }

        [HttpPost]
        [Route("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterRequest registerRequest)
        {
            IdentityUser identityUser = new IdentityUser
            {
                UserName = registerRequest.Email,
                Email = registerRequest.Email
            };

            var result = await userManager.CreateAsync(identityUser, registerRequest.Password);
            if(result.Succeeded)
            {
                return StatusCode(StatusCodes.Status201Created, new { result.Succeeded });
            }
            else
            {
                return BadRequest(result.Errors);
            }
        }

        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] RegisterRequest registerRequest)
        {
            var signInResult = await signInManager.PasswordSignInAsync(
                registerRequest.Email, registerRequest.Password, true, false);

            if(signInResult.Succeeded)
            {
                var identityUser = await userManager.FindByEmailAsync(registerRequest.Email);
                if(identityUser != null)
                {
                    var jwt = await GenerateJwt(identityUser);

                    return Ok(jwt);
                }
                else
                {
                    return NotFound();
                }
            }
            else
            {
                return Unauthorized();
            }

        }


        [NonAction]
        [ApiExplorerSettings(IgnoreApi = true)]
        private async Task<string?> GenerateJwt(IdentityUser user)
        {


            var symmetricSecurityKey = new SymmetricSecurityKey
                            (Encoding.UTF8.GetBytes(configuration["Jwt:SecretKey"] ?? ""));

            var userClaims = await userManager.GetClaimsAsync(user);

            var roles = await userManager.GetRolesAsync(user);

            var credentials = new SigningCredentials(
                symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>();

            if (roles != null)
            {
                foreach (var role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }

            claims.Add(new Claim("MyClaim", "Valore del mio claim"));


            if (userClaims != null)
            {
                claims.AddRange(userClaims);
            }


            claims.Add(new Claim(ClaimTypes.Name, user.UserName!));
            claims.Add(new Claim(ClaimTypes.Email, user.Email!));
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Email!));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

            var jwtSecurityToken = new JwtSecurityToken
                (configuration["Jwt:Issuer"], configuration["Jwt:Audience"],
                claims, DateTime.Now, DateTime.Now.AddMinutes(10),
                credentials);
            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

        }

    }
}
