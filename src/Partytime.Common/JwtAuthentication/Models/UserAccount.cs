namespace Partytime.Common.JwtAuthentication.Models
{
    public class UserAccount
    {
        public Guid Userid { get; set; }
        public string Email { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }
}
