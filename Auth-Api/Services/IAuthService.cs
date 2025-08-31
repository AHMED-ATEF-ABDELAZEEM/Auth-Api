using Auth_Api.Authentication;
using Auth_Api.Contracts.Auth.Requests;
using Auth_Api.Contracts.Auth.Responses;
using Auth_Api.CustomErrors;
using Auth_Api.CustomResult;
using Auth_Api.EmailSettings;
using Auth_Api.Models;
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

namespace Auth_Api.Services
{
    public interface IAuthService
    {
        Task<Result<AuthResponse>> GetTokenAsync (string email,string password,CancellationToken cancellationToken = default);

        Task<Result<AuthResponse>> GetRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default);

        Task<Result> RevokeRefreshTokenAsync(string token, string refreshToken, CancellationToken cancellationToken = default);

        Task<Result> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

        Task<Result> ConfirmEmailAsync(ConfirmEmailRequest request);

        Task<Result> ResendConfirmationEmailAsync(ResendConfirmationEmailRequest request);

        Task<Result> SendResetPasswordEmailAsync(string email);

        Task<Result> ResetPasswordAsync(ResetPasswordRequest request);

        Task<Result<AuthResponse>> GoogleLoginAsync(HttpContext httpContext);

    }

    public class AuthService : IAuthService
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IJwtProvider _jwtProvider;
        private readonly int _RefreshTokenExpiryDays = 14;
        private readonly ILogger<AuthService> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IEmailSender _emailSender;
        public AuthService(UserManager<ApplicationUser> userManager, IJwtProvider jwtProvider, ILogger<AuthService> logger, IHttpContextAccessor httpContextAccessor, IEmailSender emailSender, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _jwtProvider = jwtProvider;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
            _emailSender = emailSender;
            _signInManager = signInManager;
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

            if (user.PasswordHash is null)
            {
                _logger.LogWarning("Authentication failed: User with email {Email} has no password (External Login)", email);
                return Result.Failure<AuthResponse>(UserError.ExternalLogin);
            }

            if (!user.EmailConfirmed)
            {
                _logger.LogWarning("Authentication failed: User with email {Email} is not confirmed", email);
                return Result.Failure<AuthResponse>(UserError.EmailNotConfirmed);
            }

            var  result = await _signInManager.PasswordSignInAsync(user, password, false,lockoutOnFailure: true);

            if (result.IsLockedOut)
            {
                _logger.LogWarning("Authentication failed: User with email {Email} is locked out", email);
                return Result.Failure<AuthResponse>(UserError.LockedOut);
            }

            if (!result.Succeeded)
            {
                _logger.LogWarning("Authentication failed: Invalid password for user with email {Email}", email);
                return Result.Failure<AuthResponse>(UserError.InvalidCredentials);
            }

            var authResponse = await GenerateAuthResponseAsync(user);

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
                await SendConfirmationEmail(user, code);
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
            await SendConfirmationEmail(user, code);
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

            await SendResetPasswordEmail(user, code);

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






        public async Task<Result<AuthResponse>> GoogleLoginAsync(HttpContext httpContext)
        {
            var result = await httpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                _logger.LogWarning("External authentication failed.");
                return Result.Failure<AuthResponse>(ExternalAuthError.AuthenticationFailed);
            }


            var claims = result.Principal!.Claims;

            var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

            _logger.LogInformation("Starting External Login Using Google For Email : {email}", email);

            var user = await _userManager.FindByEmailAsync(email!);

            if (user is null)
            {

                var name = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
                var givenName = claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value;
                var familyName = claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value;

                user = new ApplicationUser
                {
                    Email = email,
                    UserName = email,
                    FirstName = givenName!,
                    LastName = familyName!,
                    EmailConfirmed = true,
                };

                var addResult = await _userManager.CreateAsync(user);
                if (addResult.Succeeded)
                {
                    _logger.LogInformation("Added User Successfully With Email : {email}", email);
                }
                else
                {
                    _logger.LogWarning("External authentication failed: user creation failed.");
                    var error = addResult.Errors.First();
                    return Result.Failure<AuthResponse>(new Error(error.Code, error.Description));
                }
            }

            var authResponse = await GenerateAuthResponseAsync(user);

            return Result.Success(authResponse);

        }








        private static string GenerateRefreshToken()
        {

            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        }
        
        private async Task SendConfirmationEmail(ApplicationUser user, string code)
        {
            var origin = _httpContextAccessor.HttpContext?.Request.Headers.Origin;
            var emailBody = EmailBodyBuilder.GenerateEmailBody("EmailConfirmation",
                new Dictionary<string, string>()
                {
                    { "{{name}}",user.FirstName },
                    {"{{action_url}}", $"{origin}/auth/confirm-email?userId={user.Id}&code={code}"}
                });
            await _emailSender.SendEmailAsync(user.Email!, "Survey Basket : Confirm your email", emailBody);
        }

        private async Task <AuthResponse> GenerateAuthResponseAsync(ApplicationUser user)
        {
            _logger.LogInformation("Starting Generate Token For Email : {email}", user.Email);

            // Generate JWT token
            var tokenInformation = _jwtProvider.GenerateToken(user);
            _logger.LogInformation("JWT token generated For Email : {email}", user.Email);

            // Generate Refresh Token
            var refreshToken = GenerateRefreshToken();
            var refreshTokenExpirationDate = DateTime.UtcNow.AddDays(_RefreshTokenExpiryDays);

            // Store refresh token in DB
            user.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                CreatedOn = DateTime.UtcNow,
                ExpiresOn = refreshTokenExpirationDate
            });

            await _userManager.UpdateAsync(user);
            _logger.LogInformation("Refresh token stored in database for user {Email}", user.Email);

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

            _logger.LogInformation("Authentication successful for user {Email}", user.Email);

            return authResponse;
        }

        private async Task SendResetPasswordEmail(ApplicationUser user, string code)
        {
            var origin = _httpContextAccessor.HttpContext?.Request.Headers.Origin;
            var emailBody = EmailBodyBuilder.GenerateEmailBody("ForgetPassword",
                new Dictionary<string, string>()
                {
                    { "{{name}}",user.FirstName },
                    {"{{action_url}}", $"{origin}/auth/forgot-password?email={user.Email}&code={code}"}
                });

             await _emailSender.SendEmailAsync(user.Email!, "Survey Basket : Change password", emailBody);

            _logger.LogInformation("Reset password email sent to {Email}", user.Email);

            await Task.CompletedTask;
        }

    }
}
