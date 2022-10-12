using DTOs;
using JWTApi.Services.SecurityServices;
using JWTApi.Services.ServiceResponse;
using Microsoft.AspNetCore.Identity;
using Models;
using System.Globalization;
using System.Security.Claims;
using System.Security.Principal;

namespace JWTApi.Services.UserServices
{
    public class UserService : IUserService
    {
        private readonly ISecurityServices _security;
        //Have to inject the Service
        private readonly IHttpContextAccessor _contextAccessor; 
        private static List<User> users = new List<User>();
        public UserService(ISecurityServices security, IHttpContextAccessor contextAccessor)
        {
            _security = security;
            _contextAccessor = contextAccessor;
        }
        public async Task<List<User>> Register(UserDTO request)
        {
            _security.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            var user = new User() { Username = request.Name, PasswordHash = passwordHash, PasswordSalt = passwordSalt };
            //Saving the new Properties in the users
            users.Add(user);
            return users.ToList();
        }

        public async Task<ServiceResponse<string>> Login(UserDTO request)
        {
            var userFound = users.Find(x => x.Username == request.Name);
            if (userFound == null)
                return new ServiceResponse<string>() { Message = "User not Found", Success = false };

            if (!_security.VerifyPasswordHash(request.Password, userFound.PasswordSalt, userFound.PasswordHash))
            {
                return new ServiceResponse<string>() { Message = "Incorrect Password", Success = false };
            };
            //Getting the UserToken
            string Token = _security.CreateTokenJWT(userFound);

            //Sedding the Data
            return new ServiceResponse<string>() { Data = Token };
        }

        public ServiceResponse<object> getUser()
        {
            //Acceding to the user claims that is log in
            var user = _contextAccessor.HttpContext.User;
            var UserName = user.Identity.Name;//Name of the user
            var role = user.FindFirst(ClaimTypes.Role).Value;//Role
            //Returning the values
            return new ServiceResponse<object>() { Data = new {UserName,role } };
        }
    }
}
