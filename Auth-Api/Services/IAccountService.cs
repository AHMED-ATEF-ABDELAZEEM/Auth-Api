using Auth_Api.Contracts.Account.Requests;
using Auth_Api.Contracts.Account.Responses;
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
    }
}
