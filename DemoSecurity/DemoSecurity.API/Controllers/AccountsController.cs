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
        private async Task<string?> GenerateJwt(IdentityUser user) {


            var roles = await userManager.GetRolesAsync(user);
            var claimsDb = await userManager.GetClaimsAsync(user);


            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Email, user.Email!)
                };
            claims = claims.Union(roles.Select(role => new Claim(ClaimTypes.Role, role))).ToList();
            claims = claims.Union(claimsDb).ToList();

            // await Task.Delay(100);
            JwtSecurityToken token = new JwtSecurityToken(
                issuer: configuration["Jwt:Issuer"],
                audience: configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:SecretKey"]!)),
                    SecurityAlgorithms.HmacSha256)
            );


           return new JwtSecurityTokenHandler().WriteToken(token);

        }

    }
}
