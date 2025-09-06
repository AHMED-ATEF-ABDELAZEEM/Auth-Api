using Auth_Api.Authentication;
using Auth_Api.Cache;
using Auth_Api.Contracts.Auth.Requests;
using Auth_Api.Contracts.Auth.Responses;
using Auth_Api.CustomErrors;
using Auth_Api.CustomResult;
using Auth_Api.EmailSettings;
using Auth_Api.Helpers;
using Auth_Api.Models;
using Auth_Api.Persistence;
using Auth_Api.SeedingData;
using Hangfire;
using Mapster;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using static QRCoder.PayloadGenerator;

namespace Auth_Api.Services
{
    public interface IAuthService
    {
        Task<Result<LoginResponse>> LoginAsync (string email,string password,CancellationToken cancellationToken = default);

        Task<Result<AuthResponse>> CompleteTwoFactorLoginAsync(string sessionId, string code);

        Task<Result<AuthResponse>> GetRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default);

        Task<Result> RevokeRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default);

        Task<Result> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

        Task<Result> ConfirmEmailAsync(ConfirmEmailRequest request);

        Task<Result> ResendConfirmationEmailAsync(ResendConfirmationEmailRequest request);

        Task<Result> SendResetPasswordEmailAsync(string email);

        Task<Result> ResetPasswordAsync(ResetPasswordRequest request);

        Task<Result<LoginResponse>> GoogleLoginAsync(HttpContext httpContext);

    }

    public class AuthService : IAuthService
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AppDbContext _context;
        private readonly IJwtProvider _jwtProvider;
        private readonly int _RefreshTokenExpiryDays = 14;
        private readonly ILogger<AuthService> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IEmailSender _emailSender;
        private readonly ITemporarySessionStore _temporarySessionStore;
        private readonly IAuthServiceHelper _authServiceHelper;
        private readonly IRefreshTokenHelper _refreshTokenHelper;
        public AuthService(UserManager<ApplicationUser> userManager, IJwtProvider jwtProvider, ILogger<AuthService> logger, IHttpContextAccessor httpContextAccessor, IEmailSender emailSender, SignInManager<ApplicationUser> signInManager, AppDbContext context, ITemporarySessionStore temporarySessionStore, IAuthServiceHelper authServiceHelper, IRefreshTokenHelper refreshTokenHelper)
        {
            _userManager = userManager;
            _jwtProvider = jwtProvider;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
            _emailSender = emailSender;
            _signInManager = signInManager;
            _context = context;
            _temporarySessionStore = temporarySessionStore;
            _authServiceHelper = authServiceHelper;
            _refreshTokenHelper = refreshTokenHelper;
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

            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.UtcNow)
            {
                _logger.LogWarning("Refresh token failed: user is locked out");
                return Result.Failure<AuthResponse>(UserError.LockedOut);
            }

            var userRefreshToken = await _refreshTokenHelper.GetActiveRefreshTokenAsync(userId, refreshToken);
            if (userRefreshToken is null)
            {
                _logger.LogWarning("Invalid or inactive refresh token for UserId {UserId}", user.Id);
                return Result.Failure<AuthResponse>(TokenError.InvalidToken);
            }

            
            userRefreshToken.RevokedOn = DateTime.UtcNow;
            _logger.LogInformation("Revoked old refresh token for UserId {UserId}", user.Id);

            
            var authResponse = await _authServiceHelper.GenerateAuthResponseAsync(user);

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


            var userRefreshToken = await _refreshTokenHelper.GetActiveRefreshTokenAsync(userId, refreshToken);
            if (userRefreshToken is null)
            {
                _logger.LogWarning("Invalid or inactive refresh token for UserId {UserId}", user.Id);
                return Result.Failure(TokenError.InvalidToken);
            }

            userRefreshToken.RevokedOn = DateTime.UtcNow;
            _context.RefreshTokens.Update(userRefreshToken);
            await _context.SaveChangesAsync();

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
                var roleResult = await _userManager.AddToRoleAsync(user,DefaultRoles.User);

                if (!roleResult.Succeeded)
                {
                    _logger.LogWarning("Registration failed for email: {Email}. Errors: {Errors}", request.Email, string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                    var roleError = roleResult.Errors.First();
                    return Result.Failure(new Error(roleError.Code, roleError.Description));
                }

                _logger.LogInformation("User Assign To Role Successfully");

                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                // TODO
                // You Should  send this code to the user via email for confirmation And Remove This Logging Before Production
                _logger.LogInformation("Confirmation Email: {code}", code);
                _logger.LogInformation("User Id: {userId}", user.Id);
                _logger.LogInformation("Registration Successfully for Email : {email}", user.Email);
                await _authServiceHelper.SendConfirmationEmail(user, code);
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

        public async Task<Result> ResendConfirmationEmailAsync(ResendConfirmationEmailRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user is null)
            {
                _logger.LogWarning("Resend confirmation email failed: user not found for email: {Email}", request.Email);
                // No user found, no need to resend confirmation email 
                // You Shouldnt Return That The User Not Found Error Can Be Used For Security Reasons (Attack)
                return Result.Success();
            }
            if (user.EmailConfirmed)
            {
                _logger.LogInformation("Resend confirmation email failed: Email already confirmed for email: {Email}", request.Email);
                return Result.Failure(UserError.DuplicatedConfirmation);
            }

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            // TODO
            // You Should send this code to the user via email for confirmation And Remove this line in production
            _logger.LogInformation("confirmation code : {code}", code);
            _logger.LogInformation("User Id : {Id}", user.Id);
            await _authServiceHelper.SendConfirmationEmail(user, code);
            return Result.Success();
        }

        public async Task<Result> SendResetPasswordEmailAsync(string email)
        {

            _logger.LogInformation("starting process for send reset password email To {email}", email);

            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                _logger.LogWarning("Send Reset password Email failed: user not found for email: {Email}", email);
                //  For Security Reasons (Attack)
                return Result.Success();
            }

            if (!user.EmailConfirmed)
            {
                _logger.LogWarning("Send Reset password Email failed: email not confirmed for email: {Email}", email);
                return Result.Failure(UserError.EmailNotConfirmed);
            }


            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            // TODO
            // You Should send this code to the user via email for confirmation And Remove this line in production
            _logger.LogInformation("Reset password code : {code}", code);

            await _authServiceHelper.SendResetPasswordEmail(user, code);

            _logger.LogInformation("Send Reset password Email successfully for email: {Email}", email);

            return Result.Success();
        }

        public async Task<Result> ResetPasswordAsync(ResetPasswordRequest request)
        {

            _logger.LogInformation("starting reset password process For email : {email}", request.Email);

            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user is null)
            {
                _logger.LogWarning("reset password failed: user not found for email: {Email}", request.Email);
                return Result.Failure(UserError.InvalidCode);
            }

            if (!user.EmailConfirmed)
            {
                _logger.LogWarning("reset password failed: email not confirmed for email: {Email}", request.Email);
                return Result.Failure(UserError.EmailNotConfirmed);
            }

            var code = request.Code;
            try
            {
                code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            }
            catch (FormatException)
            {
                _logger.LogWarning("reset password failed: invalid code format for email: {Email}", request.Email);
                return Result.Failure(UserError.InvalidCode);
            }


            var result = await _userManager.ResetPasswordAsync(user, code, request.NewPassword);
            if (result.Succeeded)
            {
                _logger.LogInformation("reset password successfully for email: {Email}", request.Email);
                return Result.Success();
            }

            _logger.LogWarning("reset password failed for email: {Email}. Errors: {Errors}", request.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
            var error = result.Errors.First();
            return Result.Failure(new Error(error.Code, error.Description));
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
