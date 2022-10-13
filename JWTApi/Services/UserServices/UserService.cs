using DTOs;
using JWTApi.Services.SecurityServices;
using JWTApi.Services.ServiceResponse;
using Microsoft.AspNetCore.Identity;
using Models;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using static System.Net.WebRequestMethods;

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
        public ServiceResponse<List<User>> Register(UserDTO request)
        {
            var existed = users.Where(x => x.Username == request.Name).FirstOrDefault();
            if (existed != null)
                return new ServiceResponse<List<User>>() { Message = "The user existed", Success = false };
            _security.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            var user = new User() { Username = request.Name, PasswordHash = passwordHash, PasswordSalt = passwordSalt };
            //Saving the new Properties in the users
            users.Add(user);
            return new ServiceResponse<List<User>>() { Data = users };
        }

        public ServiceResponse<string> Login(UserDTO request)
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
            //Generating the refresh Token
            var refreshToken = _security.generateRefreshToken();
            //Set the CookieOptions and the new Token
            var setRefreshToken = _security.SetRefreshToken(refreshToken);
            //Updating the Values
            userFound.RefreshToken = refreshToken.Token;
            userFound.TokenCreated = refreshToken.Created;
            userFound.TokenExpires = refreshToken.Expired;
            //Sedding the Data
            return new ServiceResponse<string>() { Data = Token };
        }

        public ServiceResponse<object> getUser()
        {
            //Acceding to the user claims that is log in
            var user = _contextAccessor.HttpContext.User;
            if (user == null)
                return new ServiceResponse<object>() { Message = "Something Happen", Success = false };
            var userName = user.FindFirstValue(ClaimTypes.Name);//Name of the user
            var role = user.FindFirstValue(ClaimTypes.Role);//Role
            //Returning the values
            return new ServiceResponse<object>() { Data = new {userName,role } };
        }

        public ServiceResponse<string> refreshToken()
        {
            var refreshToken = _contextAccessor.HttpContext.Request.Cookies["refreshToken"];
            //To Work in the controller have to put Authorize
            var user = _contextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            try
            {
                if (user == null)
                    return new ServiceResponse<string>() { Message = "Please Log In", Success = false };
                //Finding the User
                var userFound = users.Where(x => x.Username == user).FirstOrDefault();
                //Some Validations
                if (!userFound.RefreshToken.Equals(refreshToken))
                    return new ServiceResponse<string>() { Message = "Invalid Refresh Token" };
                if (userFound.TokenExpires < DateTime.Now)
                    return new ServiceResponse<string>() { Message = "Token Expired", Success = false };
                //Creating the Token and Refreshing The Token (Cokkie)
                string Token = _security.CreateTokenJWT(userFound);
                var newRefreshToken = _security.generateRefreshToken();
                //Set the CookieOptions and the new Token
                var setRefreshToken = _security.SetRefreshToken(newRefreshToken);
                //Updating the Values
                userFound.RefreshToken = newRefreshToken.Token;
                userFound.TokenCreated = newRefreshToken.Created;
                userFound.TokenExpires = newRefreshToken.Expired;

                return new ServiceResponse<string>() { Data = Token };
            }
            catch (Exception e)
            {
                return new ServiceResponse<string>() { Message = e.Message, Success = false };
            }
        }
    }
}
