using DTOs;
using JWTApi.Services.ServiceResponse;
using Models;

namespace JWTApi.Services.UserServices
{
    public interface IUserService
    {
        Task<List<User>> Register(UserDTO request);

        Task<ServiceResponse<string>> Login(UserDTO request);

        ServiceResponse<object> getUser();    
    }
}
