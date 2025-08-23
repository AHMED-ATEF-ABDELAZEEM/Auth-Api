using Auth_Api.Authentication;
using Auth_Api.Contracts.Auth.Requests;
using Auth_Api.Contracts.Auth.Responses;
using Auth_Api.CustomErrors;
using Auth_Api.CustomResult;
using Auth_Api.Models;
using Auth_Api.Persistence;
using Mapster;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace Auth_Api.Services
{
    public interface IAuthService
    {
        Task<Result<AuthResponse>> GetTokenAsync (string email,string password,CancellationToken cancellationToken = default);

        Task<Result<AuthResponse>> GetRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default);

        Task<Result> RevokeRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default);

        Task<Result> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

        Task<Result> ConfirmEmailAsync(ConfirmEmailRequest request);

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

        public async Task<Result> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Starting registration process for email: {Email}", request.Email);

            var IsEmailExist = await _userManager.Users.AnyAsync(u => u.Email == request.Email, cancellationToken);

            if (IsEmailExist)
            {
                _logger.LogWarning("Registration failed: email already exists: {Email}", request.Email);
                return Result.Failure(UserError.DuplicatedEmail);
            }

            var user = request.Adapt<ApplicationUser>();

            var result = await _userManager.CreateAsync(user, request.Password);

            if (result.Succeeded)
            {
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                // TODO
                // You Should  send this code to the user via email for confirmation And Remove This Logging Before Production
                _logger.LogInformation("Confirmation Email: {code}", code);
                _logger.LogInformation("User Id: {userId}", user.Id);
                _logger.LogInformation("Registration Successfully for Email : {email}", user.Email);
                return Result.Success();
            }

            _logger.LogWarning("Registration failed for email: {Email}. Errors: {Errors}", request.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
            var error = result.Errors.First();
            return Result.Failure(new Error(error.Code, error.Description));

        }

        public async Task<Result> ConfirmEmailAsync(ConfirmEmailRequest request)
        {

            _logger.LogInformation("Start Confirmation Email For User With Id : {Id}", request.UserId);

            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user is null)
            {
                _logger.LogWarning("Email confirmation failed: user not found for ID: {UserId}", request.UserId);
                return Result.Failure(UserError.InvalidCode);
            }

            if (user.EmailConfirmed)
            {
                _logger.LogInformation("Email confirmation failed: Email already confirmed for user ID: {UserId}", request.UserId);
                return Result.Failure(UserError.DuplicatedConfirmation);
            }

            var code = request.Code;

            try
            {
                code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            }
            catch (FormatException)
            {
                _logger.LogWarning("Email confirmation failed: invalid code format for user ID: {UserId}", request.UserId);
                return Result.Failure(UserError.InvalidCode);
            }

            var result = await _userManager.ConfirmEmailAsync(user, code);

            if (result.Succeeded)
            {
                _logger.LogInformation("Email confirmed successfully for user ID: {UserId}", request.UserId);
                return Result.Success();
            }

            _logger.LogWarning("Email confirmation failed for user ID: {UserId}. Errors: {Errors}", request.UserId, string.Join(", ", result.Errors.Select(e => e.Description)));
            var error = result.Errors.First();
            return Result.Failure(new Error(error.Code, error.Description));
        }


        private static string GenerateRefreshToken()
        {

            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        }
    }
}
