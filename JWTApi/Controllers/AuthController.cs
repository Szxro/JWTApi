using DTOs;
using JWTApi.Services.SecurityServices;
using JWTApi.Services.ServiceResponse;
using JWTApi.Services.UserServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Models;

namespace JWTApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]

        public async Task<ActionResult<User>> Register(UserDTO request) 
        {
            return Ok(await _userService.Register(request));
        }

        [HttpPost("login")]

        public async Task<ActionResult<ServiceResponse<string>>> Login(UserDTO request)
        {
            var response = await _userService.Login(request);
            if (!response.Success) 
            {
                return BadRequest(response);
            }

            return Ok(response);
       }

        [HttpGet("getUsername"), Authorize]
        public ActionResult<ServiceResponse<string>> getMe()
        {
            return Ok(_userService.getUser());
        }

    }
}
