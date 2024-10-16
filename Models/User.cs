using Microsoft.AspNetCore.Identity;

namespace WASM_Weather_Server.Models
{
    public class User : IdentityUser
    {
        //public string? Favcity { get; set; }  
        public List<string> Favcity { get; set; } = new List<string>();
    }
}
