namespace Partytime.Common.JwtAuthentication.Models
{
    public class AuthenticationResponse
    {
        public string Email { get; set; }
        public string Username { get; set; }
        public string JwtToken { get; set; }
        public int ExpiresIn { get; set; }
    }
}
