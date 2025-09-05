using Auth_Api.Contracts.Account.Requests;
using Auth_Api.Contracts.Account.Responses;
using Auth_Api.CustomErrors;
using Auth_Api.CustomResult;
using Auth_Api.Models;
using Auth_Api.Persistence;
using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using QRCoder;

namespace Auth_Api.Services
{
    public interface IAccountService
    {
        Task<Result<UserProfileResponse>> GetUserProfileAsync(string userId);

        Task<Result> UpdateProfileAsync(string userId, UpdateProfileRequest request);

        Task<Result> ChangePasswordAsync(string userId, ChangePasswordRequest request);

        Task<Result> SetPasswordAsync (string userId, SetPasswordRequest request);

        Task<Result<byte[]>> GenerateQrCodeAsync(string userId);

        Task<Result> EnableTwoFactorAsync(string userId, string code);
    }

    public class AccountService : IAccountService
    {


        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AppDbContext _context;
        private readonly ILogger<AccountService> _logger;

        public AccountService(AppDbContext context, UserManager<ApplicationUser> userManager, ILogger<AccountService> logger)
        {
            _userManager = userManager;
            _context = context;
            _logger = logger;
        }


        public async Task<Result<UserProfileResponse>> GetUserProfileAsync(string userId)
        {
            var userProfile = await _userManager.Users
                .Where(u => u.Id == userId)
                .ProjectToType<UserProfileResponse>()
                .SingleAsync();

            _logger.LogInformation("User profile retrieved for user ID: {UserId}", userId);

            return Result.Success(userProfile);

        }

        public async Task<Result> UpdateProfileAsync(string userId, UpdateProfileRequest request)
        {

            await _context.Users
                .Where(u => u.Id == userId)
                .ExecuteUpdateAsync(u => u
                    .SetProperty(x => x.FirstName, request.FirstName)
                    .SetProperty(x => x.LastName, request.LastName));

            _logger.LogInformation("User profile updated for user ID: {UserId}", userId);

            return Result.Success();
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

        public async Task<Result<byte[]>> GenerateQrCodeAsync(string userId)
        {

            _logger.LogInformation("Starting 2FA QR setup for user ID: {UserId}", userId);

            var user = await _userManager.FindByIdAsync(userId);

            if (user!.TwoFactorEnabled)
            {
                _logger.LogWarning("2FA QR setup failed: Two-factor authentication already enabled for user ID: {UserId}", userId);
                return Result.Failure<byte[]>(TwoFactorError.AlreadyEnabled);
            }

            var key = await _userManager.GetAuthenticatorKeyAsync(user);

            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            var unformattedKey = key.Replace(" ", "").Replace("-", "");
            // TODO : Change issuer name at production by your app name
            var issuer = "Auth App";
            var email = user.Email;
            var otpauthUri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}?secret={unformattedKey}&issuer={Uri.EscapeDataString(issuer)}&digits=6";

            using var qrGenerator = new QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(otpauthUri, QRCodeGenerator.ECCLevel.Q);
            var qrCode = new PngByteQRCode(qrCodeData);

            _logger.LogInformation("2FA QR setup completed for user ID: {UserId}", userId);

            return Result.Success(qrCode.GetGraphic(5));
        }
        public async Task<Result> EnableTwoFactorAsync(string userId, string code)
        {
            _logger.LogInformation("Starting Enable 2FA for user ID: {UserId}", userId);

            var user = await _userManager.FindByIdAsync(userId);

            if (user.TwoFactorEnabled)
            {
                _logger.LogWarning("Enable 2FA failed: already enabled for user ID: {UserId}", user.Id);
                return Result.Failure(TwoFactorError.AlreadyEnabled);
            }

            var cleanCode = code.Replace(" ", "").Replace("-", "");

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                cleanCode);

            if (!isValid)
            {
                _logger.LogWarning("Enable 2FA failed: invalid code for user ID: {UserId}", user.Id);
                return Result.Failure(TwoFactorError.InvalidCode);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            _logger.LogInformation("2FA enabled successfully for user ID: {UserId}", user.Id);

            return Result.Success();
        }

    }
}
