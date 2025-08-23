using Auth_Api.Authentication;
using Auth_Api.Contracts.Auth.Responses;
using Auth_Api.Models;
using Auth_Api.Persistence;
using Auth_Api.CustomResult;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;
using Auth_Api.CustomErrors;

namespace Auth_Api.Services
{
    public interface IAuthService
    {
        Task<Result<AuthResponse>> GetTokenAsync (string email,string password,CancellationToken cancellationToken = default);

        Task<Result<AuthResponse>> GetRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default);

        Task<Result> RevokeRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default);
    }

    public class AuthService : IAuthService
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IJwtProvider _jwtProvider;
        private readonly int _RefreshTokenExpiryDays = 14;
        private readonly ILogger<AuthService> _logger;
        public AuthService(UserManager<ApplicationUser> userManager, IJwtProvider jwtProvider, ILogger<AuthService> logger)
        {
            _userManager = userManager;
            _jwtProvider = jwtProvider;
            _logger = logger;
        }

        public async Task<Result<AuthResponse>> GetTokenAsync(string email, string password, CancellationToken cancellationToken = default)
        {

            _logger.LogInformation("Starting token generation process for user with email {Email}", email);

            var user = await _userManager.FindByEmailAsync(email);

            if (user is null)
            {
                _logger.LogWarning("Authentication failed: User with email {Email} not found", email);
                return Result.Failure<AuthResponse>(UserError.InvalidCredentials);
            }

            var isValidPassword = await _userManager.CheckPasswordAsync(user, password);

            if (!isValidPassword)
            {
                _logger.LogWarning("Authentication failed: Invalid password for user with email {Email}", email);
                return Result.Failure<AuthResponse>(UserError.InvalidCredentials);
            }

            // Generate JWT token
            var tokenInformation = _jwtProvider.GenerateToken(user);
            _logger.LogInformation("JWT token generated for user {UserId}", user.Id);

            // Generate Refresh Token
            var refreshToken = GenerateRefreshToken();
            var refreshTokenExpirationDate = DateTime.UtcNow.AddDays(_RefreshTokenExpiryDays);

            // Store refresh token in DB
            user.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                ExpiresOn = refreshTokenExpirationDate
            });

            await _userManager.UpdateAsync(user);
            _logger.LogInformation("Refresh token stored in database for user {UserId}", user.Id);

            var authResponse = new AuthResponse
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

            _logger.LogInformation("Authentication successful for user {UserId}", user.Id);

            return Result.Success(authResponse);
        }

        public async Task<Result<AuthResponse>> GetRefreshTokenAsync(string token,string refreshToken,CancellationToken cancellationToken = default)
        {

            _logger.LogInformation("Starting refresh token process");

            var userId = _jwtProvider.ValidateToken(token);
            if (userId is null)
            {
                _logger.LogWarning("Invalid JWT token provided");
                return Result.Failure<AuthResponse>(TokenError.InvalidToken);
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                _logger.LogWarning("User not found for UserId {UserId}", userId);
                return Result.Failure<AuthResponse>(TokenError.InvalidToken);
            }

            var userRefreshToken = user.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken && x.IsActive);
            if (userRefreshToken is null)
            {
                _logger.LogWarning("Invalid or inactive refresh token for UserId {UserId}", user.Id);
                return Result.Failure<AuthResponse>(TokenError.InvalidToken);
            }

            // Revoke the old refresh token
            userRefreshToken.RevokedOn = DateTime.UtcNow;
            _logger.LogInformation("Revoked old refresh token for UserId {UserId}", user.Id);

            // Generate new access & refresh tokens
            var newToken = _jwtProvider.GenerateToken(user);
            _logger.LogInformation("Generated new JWT for UserId {UserId}", user.Id);

            var newRefreshToken = GenerateRefreshToken();
            var newRefreshTokenExpiration = DateTime.UtcNow.AddDays(_RefreshTokenExpiryDays);

            user.RefreshTokens.Add(new RefreshToken
            {
                Token = newRefreshToken,
                ExpiresOn = newRefreshTokenExpiration
            });

            await _userManager.UpdateAsync(user);
            _logger.LogInformation("Stored new refresh token for UserId {UserId}", user.Id);

            var authResponse = new AuthResponse
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email!,
                Token = newToken.Token,
                ExpireIn = newToken.ExpiresIn * 60,
                RefreshToken = newRefreshToken,
                RefreshTokenExpiration = newRefreshTokenExpiration
            };

            _logger.LogInformation("Refresh token process completed successfully for UserId {UserId}", user.Id);

            return Result.Success(authResponse);
        }


        public async Task<Result> RevokeRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Starting refresh token revocation process");

            var userId = _jwtProvider.ValidateToken(token);
            if (userId is null)
            {
                _logger.LogWarning("Invalid JWT token provided for revocation");
                return Result.Failure(TokenError.InvalidToken);
            }


            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                _logger.LogWarning("User not found for UserId {UserId}", userId);
                return Result.Failure(TokenError.InvalidToken);
            }


            var userRefreshToken = user.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken && x.IsActive);
            if (userRefreshToken is null)
            {
                _logger.LogWarning("Invalid or inactive refresh token for UserId {UserId}", user.Id);
                return Result.Failure(TokenError.InvalidToken);
            }

            userRefreshToken.RevokedOn = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Refresh token revoked successfully for UserId {UserId}", user.Id);

            return Result.Success();
        }



        private static string GenerateRefreshToken()
        {

            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        }
    }
}
