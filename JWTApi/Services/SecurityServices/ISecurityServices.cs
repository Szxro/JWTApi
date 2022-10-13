using JWTApi.Services.ServiceResponse;
using Models;

namespace JWTApi.Services.SecurityServices
{
    public interface ISecurityServices
    {
        void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt);
        bool VerifyPasswordHash(string password,byte[] passwordSalt, byte[] passwordHash);
        string CreateTokenJWT(User user);
        RefreshToken generateRefreshToken();
        CookieOptions SetRefreshToken(RefreshToken newRefreshToken);
    }
}
