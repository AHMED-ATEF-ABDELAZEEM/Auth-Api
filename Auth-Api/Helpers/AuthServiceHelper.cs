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
        Task SendConfirmationEmail(ApplicationUser user, string code);
        Task SendResetPasswordEmail(ApplicationUser user, string code);
        Task<AuthResponse> GenerateAuthResponseAsync(ApplicationUser user);
        Task<Result<ApplicationUser>> CreateUserAsync(IEnumerable<Claim> claims);

        Task<Result<ApplicationUser>> CreateUserCoreAsync(ApplicationUser user, string? password = null);
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



        public async Task SendConfirmationEmail(ApplicationUser user, string code)
        {
            var origin = _httpContextAccessor.HttpContext?.Request.Headers.Origin;
            var emailBody = EmailBodyBuilder.GenerateEmailBody("EmailConfirmation",
                new Dictionary<string, string>()
                {
                { "{{name}}",user.FirstName },
                {"{{action_url}}", $"{origin}/auth/confirm-email?userId={user.Id}&code={code}"}
                });

            BackgroundJob.Enqueue(() => _emailSender.SendEmailAsync(user.Email!, "Survey Basket : Confirm your email", emailBody));

            await Task.CompletedTask;
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

        public async Task SendResetPasswordEmail(ApplicationUser user, string code)
        {
            var origin = _httpContextAccessor.HttpContext?.Request.Headers.Origin;
            var emailBody = EmailBodyBuilder.GenerateEmailBody("ForgetPassword",
                new Dictionary<string, string>()
                {
                { "{{name}}",user.FirstName },
                {"{{action_url}}", $"{origin}/auth/forgot-password?email={user.Email}&code={code}"}
                });

            BackgroundJob.Enqueue(() => _emailSender.SendEmailAsync(user.Email!, "Survey Basket : Reset password", emailBody));

            _logger.LogInformation("Reset password email sent to {Email}", user.Email);

            await Task.CompletedTask;
        }

        public async Task<Result<ApplicationUser>> CreateUserAsync(IEnumerable<Claim> claims)
        {

            var user = new ApplicationUser
            {
                UserName = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
                Email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
                FirstName = claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value,
                LastName = claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value,
                EmailConfirmed = true
            };

            return await CreateUserCoreAsync(user);

        }

        public async Task<Result<ApplicationUser>> CreateUserCoreAsync(ApplicationUser user, string? password = null)
        {
            _logger.LogInformation("Starting Creating User : {Email}", user.Email);

            await using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                IdentityResult addResult = new IdentityResult();
                if (password != null) addResult = await _userManager.CreateAsync(user, password);
                else addResult = await _userManager.CreateAsync(user);

                if (!addResult.Succeeded)
                {
                    var errors = string.Join(", ", addResult.Errors.Select(e => e.Description));
                    _logger.LogError("Error creating user: {ErrorMessage}", errors);

                    return Result.Failure<ApplicationUser>(UserError.RegisterFailed);

                }

                _logger.LogInformation("Added User Successfully. Id: {UserId}, Email: {Email}", user.Id, user.Email);

                var roleResult = await _userManager.AddToRoleAsync(user, DefaultRoles.User);

                if (!roleResult.Succeeded)
                {
                    var errors = string.Join(", ", roleResult.Errors.Select(e => e.Description));
                    _logger.LogError("Error Assigning role to user: {ErrorMessage}", errors);
                    await transaction.RollbackAsync();
                    return Result.Failure<ApplicationUser>(UserError.RegisterFailed);
                }

                _logger.LogInformation("User Registered Successfully With Email : {email}", user.Email);

                await transaction.CommitAsync();

                return Result.Success(user);

            }
            catch (Exception ex)
            {
                _logger.LogError("Error creating user: {ErrorMessage}", ex.Message);
                await transaction.RollbackAsync();
                return Result.Failure<ApplicationUser>(UserError.RegisterFailed);
            }
        }
    }

}
