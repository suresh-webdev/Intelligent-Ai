using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WASM_Weather_Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SupabaseConnection : ControllerBase
    {
        private readonly Supabase.Client _supabaseClient;

        public SupabaseConnection(Supabase.Client supabaseClient)
        {
            _supabaseClient = supabaseClient;
        }

        [HttpGet("test-connection")]
        public async Task<IActionResult> TestConnection()
        {
            try
            {
                var currentUser = _supabaseClient.Auth.CurrentUser;
                if (currentUser != null)
                {
                    return Ok($"Supabase connected. Authenticated user: {currentUser.Email}");
                }
                else
                {
                    return Ok("Supabase connected but no authenticated user.");
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Failed to connect to Supabase: {ex.Message}");
            }
        }
    }
}

