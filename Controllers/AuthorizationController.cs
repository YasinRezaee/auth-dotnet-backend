using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using YtMovieApis.Models;
using YtMovieApis.Models.Domain;
using YtMovieApis.Models.DTO;
using YtMovieApis.Repositories.Abstract;

namespace YtMovieApis.Controllers
{
    [Route("api/Authorization")]
    [ApiController]
    public class AuthorizationController : ControllerBase
    {
        private readonly DatabaseContext _context;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly ITokenService _tokenService;

        public AuthorizationController(DatabaseContext context,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ITokenService tokenService)
        {
            _context = context;
            this.userManager = userManager;
            this.roleManager = roleManager;
            _tokenService = tokenService;
        }

        // --- Change Password ---
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        {
            var status = new Status();
            if (!ModelState.IsValid)
            {
                status.StatusCode = 0;
                status.Message = "Please pass all the valid fields";
                return Ok(status);
            }

            var user = await userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                status.StatusCode = 0;
                status.Message = "Invalid username";
                return Ok(status);
            }

            if (!await userManager.CheckPasswordAsync(user, model.CurrentPassword))
            {
                status.StatusCode = 0;
                status.Message = "Invalid current password";
                return Ok(status);
            }

            var result = await userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                status.StatusCode = 0;
                status.Message = "Failed to change password";
                return Ok(status);
            }

            status.StatusCode = 1;
            status.Message = "Password has changed successfully";
            return Ok(status);
        }

        // --- Login ---
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.Username);
            if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = _tokenService.GetToken(authClaims);
                var refreshToken = _tokenService.GetRefreshToken();

                var tokenInfo = _context.TokenInfo.FirstOrDefault(a => a.Usename == user.UserName);
                if (tokenInfo == null)
                {
                    _context.TokenInfo.Add(new TokenInfo
                    {
                        Usename = user.UserName,
                        RefreshToken = refreshToken,
                        RefreshTokenExpiry = DateTime.Now.AddDays(1)
                    });
                }
                else
                {
                    tokenInfo.RefreshToken = refreshToken;
                    tokenInfo.RefreshTokenExpiry = DateTime.Now.AddDays(1);
                }

                try
                {
                    _context.SaveChanges();
                }
                catch (Exception ex)
                {
                    return BadRequest(ex.Message);
                }

                return Ok(new LoginResponse
                {
                    Name = user.Name,
                    Username = user.UserName,
                    Token = token.TokenString,
                    RefreshToken = refreshToken,
                    Expiration = token.ValidTo,
                    StatusCode = 1,
                    Message = "Logged in"
                });
            }

            return Ok(new LoginResponse
            {
                StatusCode = 0,
                Message = "Invalid Username or Password",
                Token = "",
                Expiration = null
            });
        }

        // --- Registration ---
        [HttpPost("register")]
        public async Task<IActionResult> Registration([FromBody] RegistrationModel model)
        {
            var status = new Status();

            // Validate input
            if (!ModelState.IsValid)
            {
                status.StatusCode = 0;
                status.Message = "Please pass all the required fields";
                return Ok(status);
            }

            // Check if username already exists
            var userExists = await userManager.FindByNameAsync(model.Username);
            if (userExists != null)
            {
                status.StatusCode = 0;
                status.Message = "Username already exists";
                return Ok(status);
            }

            // Check if email already exists
            var emailExists = await userManager.FindByEmailAsync(model.Email);
            if (emailExists != null)
            {
                status.StatusCode = 0;
                status.Message = "Email already exists";
                return Ok(status);
            }

            // Create user object
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                Name = model.Name,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            // Create the user
            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                // Return detailed errors from Identity
                status.StatusCode = 0;
                status.Message = "User creation failed: " + string.Join(", ", result.Errors.Select(e => e.Description));
                return Ok(status);
            }

            // Ensure the role exists
            if (!await roleManager.RoleExistsAsync(UserRoles.User))
                await roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            // Assign role to user
            if (await roleManager.RoleExistsAsync(UserRoles.User))
                await userManager.AddToRoleAsync(user, UserRoles.User);

            status.StatusCode = 1;
            status.Message = "Successfully registered";
            return Ok(status);
        }
    }
    }
