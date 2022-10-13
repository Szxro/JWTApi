using DTOs;
using JWTApi.Services.ServiceResponse;
using Models;

namespace JWTApi.Services.UserServices
{
    public interface IUserService
    {
        ServiceResponse<List<User>> Register(UserDTO request);

        ServiceResponse<string> Login(UserDTO request);

        ServiceResponse<object> getUser();

        ServiceResponse<string> refreshToken();
    }
}
