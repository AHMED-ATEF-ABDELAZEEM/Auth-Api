using Auth_Api.Contracts.Auth.Requests;
using Auth_Api.CustomErrors;
using Auth_Api.CustomResult;
using Auth_Api.Helpers;
using Auth_Api.Models;
using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Text;

namespace Auth_Api.Services
{
    public interface IRegistrationService
    {
        Task<Result> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);
        Task<Result> ConfirmEmailAsync(ConfirmEmailRequest request);
        Task<Result> ResendConfirmationEmailAsync(ResendConfirmationEmailRequest request);
    }

    public class RegistrationService : IRegistrationService
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<RegistrationService> _logger;
        private readonly IAuthServiceHelper _authServiceHelper;
        public RegistrationService(UserManager<ApplicationUser> userManager,
            ILogger<RegistrationService> logger,
            IAuthServiceHelper authServiceHelper)
        {
            _userManager = userManager;
            _logger = logger;
            _authServiceHelper = authServiceHelper;
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

            var result = await _authServiceHelper.CreateUserCoreAsync(user, request.Password);

            if (result.IsSuccess)
            {
                user = result.Value;
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                // TODO
                // You Should  send this code to the user via email for confirmation And Remove This Logging Before Production
                _logger.LogDebug("Confirmation Email: {code}", code);
                _logger.LogDebug("User Id: {userId}", user.Id);
                _logger.LogInformation("Registration Successfully for Email : {email}", user.Email);
                await _authServiceHelper.SendConfirmationEmail(user, code);
                return Result.Success();
            }

            _logger.LogWarning("Registration failed for email: {Email}", user.Email);
            var error = result.Error;
            return Result.Failure(error);

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
    }
}
