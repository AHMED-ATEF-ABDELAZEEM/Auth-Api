using Auth_Api.Contracts.Account.Requests;
using Auth_Api.Contracts.Account.Responses;
using Auth_Api.CustomErrors;
using Auth_Api.CustomResult;
using Auth_Api.Models;
using Auth_Api.Persistence;
using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth_Api.Services
{
    public interface IAccountService
    {
        Task<Result<UserProfileResponse>> GetUserProfileAsync(string userId);

        Task<Result> UpdateProfileAsync(string userId, UpdateProfileRequest request);

        Task<Result> ChangePasswordAsync(string userId, ChangePasswordRequest request);

        Task<Result> SetPasswordAsync (string userId, SetPasswordRequest request);
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
        
    
    }
}
