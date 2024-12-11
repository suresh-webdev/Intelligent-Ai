using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WASM_Weather_Server.Models;

namespace WASM_Weather_Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (await _userManager.FindByNameAsync(model.Username) != null || await _userManager.FindByEmailAsync(model.Email) != null)
            {
                return BadRequest(new { Message = "Username or email already exists!" });
            }

            var user = new User { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                if (await _roleManager.RoleExistsAsync(model.Role))
                {
                    await _userManager.AddToRoleAsync(user, model.Role);
                }
                else
                {
                    return BadRequest(new { Message = "Specified role does not exist!" });
                }

                return Ok(new { Message = "User created successfully!" });
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var roles = await _userManager.GetRolesAsync(user);
                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.NameIdentifier, user.Id)
                };

                foreach (var role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }

                var token = GenerateJwtToken(claims);
                SetTokenCookie(token);

                return Ok(new { Token = token });
            }

            return Unauthorized();
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("create-role")]
        public async Task<IActionResult> CreateRole([FromBody] string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName)) return BadRequest(new { Message = "Role name is required." });

            if (await _roleManager.RoleExistsAsync(roleName)) return BadRequest(new { Message = "Role already exists." });

            var result = await _roleManager.CreateAsync(new IdentityRole(roleName));

            if (result.Succeeded) return Ok(new { Message = "Role created successfully!" });

            return BadRequest(result.Errors);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] RoleAssignModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null) return NotFound(new { Message = "User not found." });

            if (!await _roleManager.RoleExistsAsync(model.Role))
                return BadRequest(new { Message = "Role does not exist." });

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            if (result.Succeeded) return Ok(new { Message = "Role assigned successfully." });

            return BadRequest(result.Errors);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("change-role")]
        public async Task<IActionResult> ChangeRole([FromBody] RoleChangeModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null) return NotFound(new { Message = "User not found." });

            if (!await _roleManager.RoleExistsAsync(model.NewRole))
                return BadRequest(new { Message = "New role does not exist." });

            var currentRoles = await _userManager.GetRolesAsync(user);
            var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);

            if (!removeResult.Succeeded) return BadRequest(new { Message = "Failed to remove existing roles." });

            var addResult = await _userManager.AddToRoleAsync(user, model.NewRole);

            if (addResult.Succeeded) return Ok(new { Message = "Role changed successfully." });

            return BadRequest(addResult.Errors);
        }


        [Authorize(Roles = "Admin")]
        [HttpGet("get-roles")]
        public IActionResult GetRoles()
        {
            var roles = _roleManager.Roles.Select(r => r.Name).ToList();
            return Ok(roles);
        }

        private string GenerateJwtToken(IEnumerable<Claim> claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("get-user-roles/{username}")]
        public async Task<IActionResult> GetUserRoles(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null) return NotFound(new { Message = "User not found." });

            var roles = await _userManager.GetRolesAsync(user);
            return Ok(roles);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("remove-user-role")]
        public async Task<IActionResult> RemoveUserRole([FromBody] RoleAssignModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null) return NotFound(new { Message = "User not found." });

            if (!await _userManager.IsInRoleAsync(user, model.Role))
                return BadRequest(new { Message = "User does not have the specified role." });

            var result = await _userManager.RemoveFromRoleAsync(user, model.Role);

            if (result.Succeeded) return Ok(new { Message = "Role removed successfully." });

            return BadRequest(result.Errors);
        }


        [Authorize(Roles = "Admin")]
        [HttpPost("remove-role")]
        public async Task<IActionResult> RemoveRole([FromBody] string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
            {
                return BadRequest("Role name cannot be empty.");
            }

            var role = await _roleManager.FindByNameAsync(roleName);
            if (role == null)
            {
                return NotFound($"Role '{roleName}' does not exist.");
            }

            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
            {
                return Ok($"Role '{roleName}' has been removed successfully.");
            }

            return StatusCode(StatusCodes.Status500InternalServerError, "Error removing role.");
        }


        [HttpGet("get-all-users-with-roles")]
        public async Task<IActionResult> GetAllUsersWithRoles()
        {
            var users = _userManager.Users.ToList();
            var userRolesList = new List<UserRoles>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userRolesList.Add(new UserRoles
                {
                    UserName = user.UserName,
                    Roles = roles.ToList()
                });
            }

            return Ok(userRolesList);
        }


        private void SetTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.Now.AddMinutes(30),
                Secure = false,
                SameSite = SameSiteMode.Lax
            };

            Response.Cookies.Append("cookieToken", token, cookieOptions);
        }
    }
}
