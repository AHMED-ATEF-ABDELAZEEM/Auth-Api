using Auth_Api.Models;
using Auth_Api.Persistence;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace Auth_Api.Helpers
{
    public interface IRefreshTokenHelper
    {
        string GenerateRefreshToken();
        Task<RefreshToken?> GetActiveRefreshTokenAsync(string userId, string refreshToken);
        Task RemoveExpiredRefreshTokensAsync();
        Task RemoveActiveRefreshTokensAsync(string userId);
    }


    public class RefreshTokenHelper : IRefreshTokenHelper
    {
        private readonly AppDbContext _context;
        private readonly ILogger<RefreshTokenHelper> _logger;

        public RefreshTokenHelper(ILogger<RefreshTokenHelper> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        public string GenerateRefreshToken()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        }
        public async Task<RefreshToken?> GetActiveRefreshTokenAsync(string userId, string refreshToken)
        {
            return await _context.RefreshTokens
                .Where(r => r.UserId == userId
                            && r.Token == refreshToken
                            && r.RevokedOn == null
                            && r.ExpiresOn > DateTime.UtcNow)
                .SingleOrDefaultAsync();
        }

        public async Task RemoveExpiredRefreshTokensAsync()
        {
            _logger.LogInformation("Start Removing expired refresh tokens");
            var refreshTokens = await _context.RefreshTokens.Where(r => r.ExpiresOn <= DateTime.UtcNow || r.RevokedOn != null).ToListAsync();
            _context.RefreshTokens.RemoveRange(refreshTokens);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Finished Removing expired refresh tokens");
        }

        public async Task RemoveActiveRefreshTokensAsync(string userId)
        {
            var refreshToken = await _context.RefreshTokens.Where(
                x => x.UserId == userId
                && x.RevokedOn == null
                && x.ExpiresOn > DateTime.UtcNow
                ).ToListAsync();
            if (refreshToken.Count == 0) return;

            _context.RefreshTokens.RemoveRange(refreshToken);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Finished Removing active refresh tokens for user Id : {userId}", userId);
        }

    }

}
