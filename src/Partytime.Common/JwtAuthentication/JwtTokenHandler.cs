using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Partytime.Common.JwtAuthentication.Models;
using RabbitMQ.Client;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;

namespace Partytime.Common.JwtAuthentication
{
    public class JwtTokenHandler
    {
        public const string JWT_SECURITY_KEY = "4931575L5X7lkupX61Zj9hWm2kV2bJ63hamt729p";
        private const int JWT_TOKEN_VALIDITY_MINS = 20;
        private readonly List<UserAccount> _userAccountList;

        public JwtTokenHandler()
        {
        }

        public async Task<string> UserAuthentication(string username, string password)
        {
            var pairs = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("password", password),
            };

            var content = new FormUrlEncodedContent(pairs);

            var client = new HttpClient { BaseAddress = new Uri("http://localhost:8001") };

            var response = await client.PostAsync("/user", content);

            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsStringAsync();
            }
                
            return "";
        }

        public async Task<AuthenticationResponse?> GenerateJwtToken(AuthenticationRequest authenticationRequest)
        {
            if (string.IsNullOrWhiteSpace(authenticationRequest.Username) || string.IsNullOrWhiteSpace(authenticationRequest.Password))
                return null;

            // Send client request to gateway for user authentication
            string isUserInDatabase = await UserAuthentication(authenticationRequest.Username, authenticationRequest.Password);
            if (isUserInDatabase.Length == 0) return null;

            // Convert client data from json string to useraccount object
            var useraccount = JsonConvert.DeserializeObject<UserAccount>(isUserInDatabase);
            if(useraccount == null) return null;

            var tokenExpiryTimeStamp = DateTime.Now.AddMinutes(JWT_TOKEN_VALIDITY_MINS);
            var tokenKey = Encoding.ASCII.GetBytes(JWT_SECURITY_KEY);
            var claimsIdentity = new ClaimsIdentity(new List<Claim>
            {
                new Claim(ClaimTypes.Name, useraccount.Userid.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, useraccount.Email),
                new Claim(JwtRegisteredClaimNames.Name, authenticationRequest.Username),
                new Claim("Role", useraccount.Role),
            });

            var signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(tokenKey),
                SecurityAlgorithms.HmacSha256Signature);

            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claimsIdentity,
                Expires = tokenExpiryTimeStamp,
                SigningCredentials = signingCredentials
            };

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = jwtSecurityTokenHandler.WriteToken(securityToken);

            return new AuthenticationResponse
            {
                Userid = useraccount.Userid,
                Email = useraccount.Email,
                Username = useraccount.Username,
                Role = useraccount.Role,
                ExpiresIn = (int)tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds,
                JwtToken = token
            };
        }
    }
}

