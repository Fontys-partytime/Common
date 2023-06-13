using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Npgsql;
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
        public const string UserDatabaseConnectionString = "Server=authentication.postgres.database.azure.com;Database=users;Port=5432;User Id=tomoli;Password=34Bn473OaN76qBT7;Ssl Mode=Require;Trust Server Certificate=true;";
        private const int JWT_TOKEN_VALIDITY_MINS = 20;


        public async Task<UserAccount?> GetUser(string username, string password)
        {
            UserAccount account = new UserAccount();
            NpgsqlConnection conn = new NpgsqlConnection(UserDatabaseConnectionString);

            conn.Open();

            // Obtain user
            NpgsqlCommand command = new NpgsqlCommand("SELECT * FROM users WHERE username = '" + username + "'", conn);

            // Execute the query and obtain a result set
            NpgsqlDataReader reader = await command.ExecuteReaderAsync();

            while (reader.Read())
            {
                account.Id = new Guid(reader["id"].ToString() ?? "");
                account.Username = reader["username"].ToString() ?? "";
                account.Email = reader["email"].ToString() ?? "";
                account.Password = reader["password"].ToString() ?? "";
                account.Role = reader["role"].ToString() ?? "";
            }

            reader.Close();

            command.Dispose();
            conn.Close();

            bool isValidPassword = BCrypt.Net.BCrypt.Verify(password, account.Password);

            if (isValidPassword)
            {
                return account;
            }

            return null;
        }

        public async Task<AuthenticationResponse?> GenerateJwtToken(AuthenticationRequest authenticationRequest)
        {
            if (string.IsNullOrWhiteSpace(authenticationRequest.Username) || string.IsNullOrWhiteSpace(authenticationRequest.Password))
                return null;

            // Convert client data from json string to useraccount object
            UserAccount? useraccount = await GetUser(authenticationRequest.Username, authenticationRequest.Password);
            if(useraccount == null) return null;

            var tokenExpiryTimeStamp = DateTime.Now.AddMinutes(JWT_TOKEN_VALIDITY_MINS);
            var tokenKey = Encoding.ASCII.GetBytes(JWT_SECURITY_KEY);
            var claimsIdentity = new ClaimsIdentity(new List<Claim>
            {
                new Claim(ClaimTypes.Name, useraccount.Id.ToString()),
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
                Userid = useraccount.Id,
                Email = useraccount.Email,
                Username = useraccount.Username,
                Role = useraccount.Role,
                ExpiresIn = (int)tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds,
                JwtToken = token
            };
        }
    }
}

