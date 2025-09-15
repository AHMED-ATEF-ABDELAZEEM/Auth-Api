using Auth_Api.Authentication;
using Auth_Api.Cache;
using Auth_Api.Contracts.Auth.Responses;
using Auth_Api.CustomErrors;
using Auth_Api.CustomResult;
using Auth_Api.EmailSettings;
using Auth_Api.Models;
using Auth_Api.Persistence;
using Auth_Api.SeedingData;
using Auth_Api.Services;
using Hangfire;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Auth_Api.Helpers
{

    public interface IAuthServiceHelper
    {

        Task<AuthResponse> GenerateAuthResponseAsync(ApplicationUser user);

    }

    public class AuthServiceHelper : IAuthServiceHelper
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AppDbContext _context;
        private readonly IJwtProvider _jwtProvider;
        private readonly int _RefreshTokenExpiryDays = 14;
        private readonly ILogger<AuthServiceHelper> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IEmailSender _emailSender;
        private readonly IRefreshTokenHelper _refreshTokenHelper;

        public AuthServiceHelper(
            UserManager<ApplicationUser> userManager,
            IJwtProvider jwtProvider,
            ILogger<AuthServiceHelper> logger,
            IHttpContextAccessor httpContextAccessor,
            IEmailSender emailSender,
            AppDbContext context,
            IRefreshTokenHelper refreshTokenHelper)
        {
            _userManager = userManager;
            _jwtProvider = jwtProvider;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
            _emailSender = emailSender;
            _context = context;
            _refreshTokenHelper = refreshTokenHelper;
        }



        public async Task<AuthResponse> GenerateAuthResponseAsync(ApplicationUser user)
        {
            _logger.LogInformation("Starting Generate Token For Email : {email}", user.Email);

            var userRoles = await _userManager.GetRolesAsync(user);
            var tokenInformation = _jwtProvider.GenerateToken(user, userRoles);
            _logger.LogInformation("JWT token generated For Email : {email}", user.Email);

            var refreshToken = _refreshTokenHelper.GenerateRefreshToken();
            var refreshTokenExpirationDate = DateTime.UtcNow.AddDays(_RefreshTokenExpiryDays);

            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                CreatedOn = DateTime.UtcNow,
                ExpiresOn = refreshTokenExpirationDate,
                UserId = user.Id
            };
            await _context.RefreshTokens.AddAsync(refreshTokenEntity);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Refresh token stored in database for user {Email}", user.Email);

            return new AuthResponse
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email!,
                Token = tokenInformation.Token,
                ExpireIn = tokenInformation.ExpiresIn * 60,
                RefreshToken = refreshToken,
                RefreshTokenExpiration = refreshTokenExpirationDate
            };
        }



    }

}
