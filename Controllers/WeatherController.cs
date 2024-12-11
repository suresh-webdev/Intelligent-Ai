using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using WASM_Weather_Server.Models;

namespace WASM_Weather_Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class WeatherController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager; // Role management if you are using roles
        private readonly IConfiguration _configuration;

        // Inject UserManager and RoleManager
        public WeatherController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpGet("favcity")]
        [Authorize]
        public async Task<IActionResult> GetFavCity()
        {
            var userName = User.FindFirst(ClaimTypes.NameIdentifier)?.Value; // Use this claim
          
            Console.WriteLine("Username is: " + userName);  // Note the correct syntax for string interpolation
            
            if (string.IsNullOrEmpty(userName))
            {
                return NotFound("User not found.");
            }

            var user = await _userManager.FindByNameAsync(userName);
            if (user == null)
            {
                return NotFound();
            }

            return Ok(user.Favcity);
        }

        [HttpPost("favcity")]
        [Authorize]
        public async Task<IActionResult> UpdateFavCity([FromBody] List<string> favoriteCities)
        {
            // Extract the username from the claims
            var userName = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userName))
            {
                return NotFound("User not found.");
            }

            // Find the user by username
            var user = await _userManager.FindByNameAsync(userName);
            if (user == null)
            {
                return NotFound();
            }

            // Check if favoriteCities is null or empty
            if (favoriteCities == null || !favoriteCities.Any())
            {
                return BadRequest("Favorite cities cannot be null or empty.");
            }

            // Update the user's favorite cities
            user.Favcity = favoriteCities;
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok(user.Favcity);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("favcity/add")]
        //[Authorize]
        public async Task<IActionResult> AddFavCity([FromBody] string city)
        {
            var userName = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userName))
            {
                return NotFound("User not found.");
            }

            var user = await _userManager.FindByNameAsync(userName);
            if (user == null)
            {
                return NotFound();
            }

            if (string.IsNullOrWhiteSpace(city))
            {
                return BadRequest("City cannot be null or empty.");
            }

            // Add the city if it does not already exist in the user's favorite cities
            if (user.Favcity == null)
            {
                user.Favcity = new List<string>();
            }

            if (!user.Favcity.Contains(city))
            {
                user.Favcity.Add(city);
                var result = await _userManager.UpdateAsync(user);

                if (!result.Succeeded)
                {
                    return BadRequest(result.Errors);
                }
            }
            else
            {
                return BadRequest("City already exists in your favorite list.");
            }

            return Ok(user.Favcity);
        }

        [HttpDelete("favcity/remove")]
        [Authorize]
        public async Task<IActionResult> RemoveFavCity([FromQuery] string city)
        {
            var userName = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userName))
            {
                return NotFound("User not found.");
            }

            var user = await _userManager.FindByNameAsync(userName);
            if (user == null)
            {
                return NotFound();
            }

            if (string.IsNullOrWhiteSpace(city))
            {
                return BadRequest("City cannot be null or empty.");
            }

            // Check if the city exists in the user's favorite cities
            if (user.Favcity != null && user.Favcity.Contains(city))
            {
                user.Favcity.Remove(city);
                var result = await _userManager.UpdateAsync(user);

                if (!result.Succeeded)
                {
                    return BadRequest(result.Errors);
                }
            }
            else
            {
                return BadRequest("City does not exist in your favorite list.");
            }

            return Ok(user.Favcity);
        }

       

    }
}
