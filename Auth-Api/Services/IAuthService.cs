using Auth_Api.Authentication;
using Auth_Api.Cache;
using Auth_Api.Contracts.Account.Requests;
using Auth_Api.Contracts.Auth.Requests;
using Auth_Api.Contracts.Auth.Responses;
using Auth_Api.CustomErrors;
using Auth_Api.CustomResult;
using Auth_Api.EmailSettings;
using Auth_Api.Helpers;
using Auth_Api.Models;
using Mapster;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Text;

namespace Auth_Api.Services
{

    public interface IAuthService
    {
        Task<Result<LoginResponse>> LoginAsync (string email,string password,CancellationToken cancellationToken = default);

        Task<Result<AuthResponse>> CompleteTwoFactorLoginAsync(string sessionId, string code);

        Task<Result<LoginResponse>> GoogleLoginAsync(HttpContext httpContext);

    }

    public class AuthService : IAuthService
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AuthService> _logger;
        private readonly ITemporarySessionStore _temporarySessionStore;
        private readonly IAuthServiceHelper _authServiceHelper;
        public AuthService(UserManager<ApplicationUser> userManager,
            ILogger<AuthService> logger,
            SignInManager<ApplicationUser> signInManager,
            ITemporarySessionStore temporarySessionStore,
            IAuthServiceHelper authServiceHelper)
        {
            _userManager = userManager;
            _logger = logger;
            _signInManager = signInManager;
            _temporarySessionStore = temporarySessionStore;
            _authServiceHelper = authServiceHelper;
        }

        public async Task<Result<LoginResponse>> LoginAsync(string email, string password, CancellationToken cancellationToken = default)
        {

            _logger.LogInformation("Starting Login process for user with email {Email}", email);

            var user = await _userManager.FindByEmailAsync(email);

            if (user is null)
            {
                _logger.LogWarning("Authentication failed: User with email {Email} not found", email);
                return Result.Failure<LoginResponse>(UserError.InvalidCredentials);
            }

            if (user.PasswordHash is null)
            {
                _logger.LogWarning("Authentication failed: User with email {Email} has no password (External Login)", email);
                return Result.Failure<LoginResponse>(UserError.ExternalLogin);
            }

            if (!user.EmailConfirmed)
            {
                _logger.LogWarning("Authentication failed: User with email {Email} is not confirmed", email);
                return Result.Failure<LoginResponse>(UserError.EmailNotConfirmed);
            }

            var  result = await _signInManager.PasswordSignInAsync(user, password, false,lockoutOnFailure: true);

            if (result.IsLockedOut)
            {
                _logger.LogWarning("Authentication failed: User with email {Email} is locked out", email);
                return Result.Failure<LoginResponse>(UserError.LockedOut);
            }

            var loginResponse = new LoginResponse();


            if (result.RequiresTwoFactor)
            {
                _logger.LogInformation("Two-Factor Authentication required. Generating temporary session for user : {email}",user.Email);
                var sessionId = Guid.NewGuid().ToString();
                await _temporarySessionStore.SetAsync(sessionId, user.Id, TimeSpan.FromMinutes(2));
                loginResponse.RequiresTwoFactor = true;
                loginResponse.SessionId = sessionId;
                _logger.LogInformation("Temporary 2FA session stored successfully.");
                return Result.Success(loginResponse);

            }

            if (!result.Succeeded)
            {
                _logger.LogWarning("Authentication failed: Invalid password for user with email {Email}", email);
                return Result.Failure<LoginResponse>(UserError.InvalidCredentials);
            }

            var authResponse = await _authServiceHelper.GenerateAuthResponseAsync(user);

            loginResponse.AuthResponse = authResponse;

            _logger.LogInformation("Authentication Success for user with email {Email}", email);

            return Result.Success(loginResponse);
        }


        public async Task<Result<AuthResponse>> CompleteTwoFactorLoginAsync(string sessionId, string code)
        {

            _logger.LogInformation("Starting 2FA login process for session ID: {SessionId}", sessionId);

            var userId = await _temporarySessionStore.GetAsync(sessionId);
            if (userId == null)
            {
                _logger.LogWarning("2FA login failed: Invalid session ID: {SessionId}", sessionId);
                return Result.Failure<AuthResponse>(TwoFactorError.InvalidSession);
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("2FA login failed: User not found for session ID: {SessionId}", sessionId);
                return Result.Failure<AuthResponse>(TwoFactorError.InvalidSession);
            }

            var cleanCode = code.Replace(" ", "").Replace("-", "");

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                TokenOptions.DefaultAuthenticatorProvider,
                cleanCode);

            if (!isValid)
            {
                _logger.LogWarning("2FA login failed: Invalid code for User : {Email}", user.Email);
                return Result.Failure<AuthResponse>(TwoFactorError.InvalidCode);
            }

            var authResponse = await _authServiceHelper.GenerateAuthResponseAsync(user);

            await _temporarySessionStore.RemoveAsync(sessionId);
            _logger.LogInformation("Remove session for User : {Email}", user.Email);
            _logger.LogInformation("2FA login Success for User : {Email}", user.Email);
            return Result.Success(authResponse);
        }

        public async Task<Result<LoginResponse>> GoogleLoginAsync(HttpContext httpContext)
        {
            var result = await httpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                _logger.LogWarning("External authentication failed.");
                return Result.Failure<LoginResponse>(ExternalAuthError.AuthenticationFailed);
            }


            var claims = result.Principal!.Claims;

            var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;


            var emailVerifiedClaim = claims.FirstOrDefault(c => c.Type == "email_verified")?.Value;

            bool.TryParse(emailVerifiedClaim,out bool  emailVerified);

            if (email is null)
            {
                _logger.LogWarning("External authentication failed: user email not found in claims.");
                return Result.Failure<LoginResponse>(ExternalAuthError.UserEmailNotFound);
            }

            if (!emailVerified)
            {
                _logger.LogWarning("External authentication failed: user email not verified.");
                return Result.Failure<LoginResponse>(ExternalAuthError.UserEmailNotVerified);
            }

            _logger.LogInformation("Starting External Login Using Google For Email : {email}", email);

            var user = await _userManager.FindByEmailAsync(email!);

            if (user is null)
            {
                var createResult = await _authServiceHelper.CreateUserAsync(claims);

                if (createResult.IsSuccess)
                {
                    user = createResult.Value;
                }
                else
                {
                    return Result.Failure<LoginResponse>(createResult.Error);
                }

            }

            var loginResponse = new LoginResponse();


            if (user.TwoFactorEnabled)
            {
                _logger.LogInformation("Two-Factor Authentication required. Generating temporary session for user : {email}", user.Email);
                var sessionId = Guid.NewGuid().ToString();
                await _temporarySessionStore.SetAsync(sessionId, user.Id, TimeSpan.FromMinutes(2));
                loginResponse.RequiresTwoFactor = true;
                loginResponse.SessionId = sessionId;
                _logger.LogInformation("Temporary 2FA session stored successfully.");
                return Result.Success(loginResponse);

            }
            var authResponse = await _authServiceHelper.GenerateAuthResponseAsync(user);

            loginResponse.AuthResponse = authResponse;


            return Result.Success(loginResponse);

        }



    }
}
