using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Supabase;
using Supabase.Gotrue;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Threading.Tasks;
using Client = Supabase.Client;

namespace WASM_Weather_Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SupabaseAuthController : ControllerBase
    {
        private readonly Client _supabaseClient;

        

        public SupabaseAuthController(Client supabaseClient)
        {
            _supabaseClient = supabaseClient;
        }

        [HttpPost("signup")]
        public async Task<IActionResult> SignUp([FromBody] SignUpRequest request)
        {
            // Ensure the SignUpOptions includes the role from the request
            var signUpOptions = new SignUpOptions
            {
                Data = new Dictionary<string, object> { { "role", request.Role } } // Correctly accessing request.Role
            };

            // Pass the signUpOptions into the SignUp call
            var response = await _supabaseClient.Auth.SignUp(request.Email, request.Password, signUpOptions);

            if (response.User != null)
            {
                return Ok(new
                {
                    Message = "User registered successfully.",
                    User = response.User.Email,
                    Role = request.Role  // Optional: return the role
                });
            }
            return BadRequest(new { Message = "Registration failed." });
        }

        [HttpPost("signin")]
        public async Task<IActionResult> SignIn([FromBody] SignInRequest request)
        {
            var response = await _supabaseClient.Auth.SignIn(request.Email, request.Password);

            if (response.User != null)
            {
                // Accessing the user's metadata
                var userRole = response.User.UserMetadata.ContainsKey("role")
                    ? response.User.UserMetadata["role"].ToString()
                    : "No role assigned";

                return Ok(new
                {
                    Message = "User signed in successfully.",
                    User = response.User.Email,
                    Role = userRole  // Return the role in the response
                });
            }

            return BadRequest(new { Message = "Sign-in failed." });
        }

        [HttpGet("protected")]
        public IActionResult ProtectedEndpoint()
        {
            var user = _supabaseClient.Auth.CurrentUser;

            if (user != null)
            {
                var userRole = user.UserMetadata.ContainsKey("role")
                    ? user.UserMetadata["role"].ToString()
                    : "No role assigned";

                // Example role check: Only allow 'admin'
                if (userRole == "Admin")
                {
                    return Ok(new { Message = "Welcome, admin!" });
                }
                else
                {
                    return Unauthorized(new { Message = "You do not have access to this resource." });
                }
            }

            return Unauthorized(new { Message = "User not logged in." });
        }

    }

    public class SignUpRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }

        [Required]
        public string Role { get; set; }
    }

    public class SignInRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }
    }
}
