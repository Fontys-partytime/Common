namespace Partytime.Common.JwtAuthentication.Models
{
    public class AuthenticationResponse
    {
        public Guid Userid { get; set; }
        public string Email { get; set; }
        public string Username { get; set; }
        public string Role { get; set; }
        public string JwtToken { get; set; }
        public int ExpiresIn { get; set; }
    }
}
