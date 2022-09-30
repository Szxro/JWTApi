using DTOs;
using JWTApi.Services.SecurityServices;
using JWTApi.Services.ServiceResponse;
using Models;
using System.Globalization;

namespace JWTApi.Services.UserServices
{
    public class UserService : IUserService
    {
        private readonly ISecurityServices _security;
        private static List<User> users = new List<User>();
        public UserService(ISecurityServices security)
        {
          _security = security;
        }
        public async Task<List<User>> Register(UserDTO request)
        {
            _security.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            var user = new User() { Username = request.Name, PasswordHash = passwordHash, PasswordSalt = passwordSalt };
            //Saving the new Properties in the users
            users.Add(user);
            return users.ToList();
        }

        public async  Task<ServiceResponse<string>> Login(UserDTO request)
        {
            var userFound = users.Find(x => x.Username == request.Name);
            if (userFound == null)
                return new ServiceResponse<string>() {Message ="User not Found", Success = false };

            if (!_security.VerifyPasswordHash(request.Password, userFound.PasswordSalt, userFound.PasswordHash))
            {
                return new ServiceResponse<string>() { Message = "Incorrect Password", Success = false };
            };
            //Getting the UserToken
            string Token = _security.CreateTokenJWT(userFound);

            //Sedding the Data
            return new ServiceResponse<string>() { Data = Token };
        }
    }
}
