using Auth_Api.Contracts.Account.Requests;
using Auth_Api.Contracts.Auth.Requests;
using Auth_Api.CustomErrors;
using Auth_Api.CustomResult;
using Auth_Api.Helpers;
using Auth_Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace Auth_Api.Services
{
    public interface IPasswordService
    {
        Task<Result> ChangePasswordAsync(string userId, ChangePasswordRequest request);
        Task<Result> SetPasswordAsync(string userId, SetPasswordRequest request);
        Task<Result> SendResetPasswordEmailAsync(string email);
        Task<Result> ResetPasswordAsync(ResetPasswordRequest request);
    }

    public class PasswordService : IPasswordService
    {

        private readonly UserManager<ApplicationUser> _userManager;

        private readonly ILogger<AuthService> _logger;

        private readonly IEmailHelper _emailHelper;

        private readonly IAuthServiceHelper _authServiceHelper;

        public PasswordService(UserManager<ApplicationUser> userManager,
            ILogger<AuthService> logger,
            IAuthServiceHelper authServiceHelper,
            IEmailHelper emailHelper)
        {
            _userManager = userManager;
            _logger = logger;
            _authServiceHelper = authServiceHelper;
            _emailHelper = emailHelper;
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

            await _emailHelper.SendResetPasswordEmail(user, code);

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

        public async Task<Result> ChangePasswordAsync(string userId, ChangePasswordRequest request)
        {
            _logger.LogInformation("starting change Password for userId : {userId}", userId);

            var user = await _userManager.FindByIdAsync(userId);

            // Check For External Login That Doestnt Has Password
            if (user!.PasswordHash == null)
            {
                _logger.LogWarning("Failed to change password for user ID: {UserId}. User does not have a password", userId);
                return Result.Failure(UserError.NoPasswordSet);
            }


            var result = await _userManager.ChangePasswordAsync(user!, request.currentPassword, request.newPassword);

            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to change password for user ID: {UserId}", userId);
                var error = result.Errors.First();
                return Result.Failure(new Error(error.Code, error.Description));
            }


            _logger.LogInformation("Password changed successfully for user ID: {UserId}", userId);
            return Result.Success();

        }

        public async Task<Result> SetPasswordAsync(string userId, SetPasswordRequest request)
        {
            _logger.LogInformation("Starting set password process for user ID: {UserId}", userId);

            var user = await _userManager.FindByIdAsync(userId);


            if (user!.PasswordHash != null)
            {
                _logger.LogWarning("Set password failed: User already has a password set for ID: {UserId}", userId);
                return Result.Failure(UserError.PasswordAlreadySet);
            }

            var result = await _userManager.AddPasswordAsync(user, request.Password);

            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed to set password for user ID: {UserId}", userId);
                var error = result.Errors.First();
                return Result.Failure(new Error(error.Code, error.Description));
            }

            _logger.LogInformation("Password set successfully for user ID: {UserId}", userId);
            return Result.Success();
        }


    }

}
