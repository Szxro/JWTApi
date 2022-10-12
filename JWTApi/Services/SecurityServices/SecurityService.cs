using Microsoft.IdentityModel.Tokens;
using Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWTApi.Services.SecurityServices
{
    public class SecurityService : ISecurityServices
    {
        private readonly IConfiguration _configuration;
        public SecurityService(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                //Creating the passwordSalt
                passwordSalt = hmac.Key;
                //Creating the passwordHash (enconding the password boths)
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        public string CreateTokenJWT(User user)
        {
            //Making the claims
            List<Claim> claim = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,user.Username),
                new Claim(ClaimTypes.Role,"Noob")
            };

            //Making the SecurityKey
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

            //Making the Credentials
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            //Making the Token
            var token = new JwtSecurityToken
                (
                    claims: claim,
                    //When the Token is going to expire
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: creds
                );

            //Making the jwtHandler
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        public bool VerifyPasswordHash(string password, byte[] passwordSalt, byte[] passwordHash)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
                /* 
                 return computedHash == passwordHash; 
                This is just return true or false if the computedHash that is given is equal to the passwordHash
                 */
            }
        }
    }
}
