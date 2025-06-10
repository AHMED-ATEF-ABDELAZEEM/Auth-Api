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
        public AuthService(UserManager<ApplicationUser> userManager,IJwtProvider jwtProvider)
        {
            _userManager = userManager;
            _jwtProvider = jwtProvider;
        }

        public async Task<Result<AuthResponse>> GetTokenAsync(string email, string password, CancellationToken cancellationToken = default)
        {
            // Check if the user exists
            var User = await _userManager.FindByEmailAsync(email);

            if (User is null) return Result.Failure<AuthResponse>(UserError.InvalidCredentials);

            // Check if the password is correct

            var IsValidPassword = await _userManager.CheckPasswordAsync(User, password);

            if (!IsValidPassword) return Result.Failure<AuthResponse>(UserError.InvalidCredentials);
            // Generate a JWT token

            var TokenInformation = _jwtProvider.GenerateToken(User);

            // Generate Refresh Token

            var RefreshToken = GenerateRefreshToken();

            var RefreshTokenExpirationDate = DateTime.UtcNow.AddDays(_RefreshTokenExpiryDays);

            // Store the refresh token in the database
            User.RefreshTokens.Add(new RefreshToken
            {
                Token = RefreshToken,
                ExpiresOn = RefreshTokenExpirationDate
            });

            await _userManager.UpdateAsync(User);


            var AuthResponse =  new AuthResponse
            {
                Id = User.Id,
                FirstName = User.FirstName,
                LastName = User.LastName,
                Email = User.Email,
                Token = TokenInformation.Token,
                ExpireIn = TokenInformation.ExpiresIn * 60,
                RefreshToken = RefreshToken,
                RefreshTokenExpiration = RefreshTokenExpirationDate
            };

            return Result.Success(AuthResponse);
        }

        public async Task<Result<AuthResponse>> GetRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default)
        {
            var UserId = _jwtProvider.ValidateToken(token);
            if (UserId is null) return Result.Failure<AuthResponse>(TokenError.InvalidToken);

            var User = await _userManager.FindByIdAsync(UserId);
            if (User is null) return Result.Failure<AuthResponse>(TokenError.InvalidToken);

            var UserRefreshToken = User.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken && x.IsActive);
            if (UserRefreshToken is null) return Result.Failure<AuthResponse>(TokenError.InvalidToken);

            UserRefreshToken.RevokedOn = DateTime.UtcNow;

            var NewToken = _jwtProvider.GenerateToken(User);
            var NewRefreshToken = GenerateRefreshToken();
            var NewRefreshTokenExpiration = DateTime.UtcNow.AddDays(_RefreshTokenExpiryDays);

            User.RefreshTokens.Add(new RefreshToken
            {
                Token = NewRefreshToken,
                ExpiresOn = NewRefreshTokenExpiration
            });

            await _userManager.UpdateAsync(User);

            var AuthResponse = new AuthResponse
            {
                Id = User.Id,
                FirstName = User.FirstName,
                LastName = User.LastName,
                Email = User.Email,
                Token = NewToken.Token,
                ExpireIn = NewToken.ExpiresIn * 60,
                RefreshToken = NewRefreshToken,
                RefreshTokenExpiration = NewRefreshTokenExpiration
            };

            return Result.Success(AuthResponse);

        }


        public async Task<Result> RevokeRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default)
        {
            var UserId = _jwtProvider.ValidateToken(token);
            if (UserId is null) return Result.Failure(TokenError.InvalidToken);

            var User = await _userManager.FindByIdAsync(UserId);
            if (User is null) return Result.Failure(TokenError.InvalidToken);

            var UserRefreshToken = User.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken && x.IsActive);
            if (UserRefreshToken is null) return Result.Failure(TokenError.InvalidToken);

            UserRefreshToken.RevokedOn = DateTime.UtcNow;

            await _userManager.UpdateAsync(User);
            return Result.Success();
        }



        private static string GenerateRefreshToken()
        {

            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        }
    }
}
