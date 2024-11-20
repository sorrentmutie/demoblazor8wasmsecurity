using System.ComponentModel.DataAnnotations;

namespace DemoSecurity.Models;

public class RegisterRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = "";

    [Required]
    [StringLength(100, ErrorMessage = "Password non complessa", MinimumLength = 6)]
    public  string Password { get; set; } = "";

}
