using Auth_Api.Authentication;
using Auth_Api.Contracts.Auth.Responses;
using Auth_Api.Models;
using Auth_Api.Persistence;
using Microsoft.AspNetCore.Identity;

namespace Auth_Api.Services
{
    public interface IAuthService
    {
        Task<AuthResponse?> GetTokenAsync (string email,string password,CancellationToken cancellationToken = default); 
    }

    public class AuthService : IAuthService
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IJwtProvider _jwtProvider;
        public AuthService(UserManager<ApplicationUser> userManager,IJwtProvider jwtProvider)
        {
            _userManager = userManager;
            _jwtProvider = jwtProvider;
        }

        public async Task<AuthResponse?> GetTokenAsync(string email, string password, CancellationToken cancellationToken = default)
        {
            // Check if the user exists
            var User = await _userManager.FindByEmailAsync(email);

            if (User is null) return null;

            // Check if the password is correct

            var IsValidPassword = await _userManager.CheckPasswordAsync(User, password);

            if (!IsValidPassword) return null;

            // Generate a JWT token

            var TokenInformation = _jwtProvider.GenerateToken(User);

            // Return the token and user information
            return new AuthResponse
            {
                Id = User.Id,
                FirstName = User.FirstName,
                LastName = User.LastName,
                Email = User.Email,
                Token = TokenInformation.Token,
                ExpireIn = TokenInformation.ExpiresIn * 60,
            };
        }


    }
}
