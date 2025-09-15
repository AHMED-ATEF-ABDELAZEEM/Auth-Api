using Auth_Api.Consts;
using Auth_Api.Contracts.Account.Requests;
using Auth_Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Identity.Client;
using System.Security.Claims;

namespace Auth_Api.Controllers
{
    [Route("me")]
    [ApiController]
    [Authorize]
    [EnableRateLimiting(RateLimiters.UserLimit)]
    public class AccountsController : ControllerBase
    {
        private readonly IAccountService _accountService;
        private readonly IImageProfileService _imageProfileService;
        private readonly IPasswordService _passwordService;
        public AccountsController(IAccountService accountService, IImageProfileService imageProfileService, IPasswordService passwordService)
        {
            _accountService = accountService;
            _imageProfileService = imageProfileService;
            _passwordService = passwordService;
        }


        [HttpGet("")]
        public async Task<IActionResult> GetUserProfile()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _accountService.GetUserProfileAsync(userId!);
            return Ok(result.Value);
        }

        [HttpPut("")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            await _accountService.UpdateProfileAsync(userId!, request);
            return NoContent();
        }

        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _passwordService.ChangePasswordAsync(userId!, request);

            return result.IsSuccess ? NoContent() : BadRequest(result.Error);

        }

        [HttpPut("set-password")]
        public async Task<IActionResult> SetPassword([FromBody] SetPasswordRequest request)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _passwordService.SetPasswordAsync(userId!, request);
            return result.IsSuccess ? NoContent() : BadRequest(result.Error);
        }

        [HttpGet("2fa/setup")]
        public async Task<IActionResult> Get2FaQrCode()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _accountService.GenerateQrCodeAsync(userId!);

            return result.IsSuccess ? File(result.Value, "image/png") : BadRequest(result.Error);
        }

        [HttpPost("2fa/enable")]
        public async Task<IActionResult> Enable2Fa([FromBody] EnableTwoFactorRequest request)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var result = await _accountService.EnableTwoFactorAsync(userId, request.Code);

            return result.IsSuccess ? Ok("2FA enabled successfully") : BadRequest(result.Error);
        }

        [HttpPost("2fa/disable")]
        public async Task<IActionResult> Disable2Fa([FromBody] DisableTwoFactorRequest request)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var result = await _accountService.DisableTwoFactorAsync(userId, request.Code);

            return result.IsSuccess ? Ok("2FA disabled successfully") : BadRequest(result.Error);
        }

        [HttpPost("profile-image")]
        public async Task<IActionResult> UploadProfileImage([FromForm] IFormFile Image,CancellationToken cancellationToken = default)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var result = await _imageProfileService.UploadProfileImageAsync(userId, Image, cancellationToken);

            return result.IsSuccess ? Ok(result.Value) : BadRequest(result.Error);
        }

        [HttpDelete("profile-image")]
        public async Task<IActionResult> DeleteProfileImage(CancellationToken cancellationToken = default)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var result = await _imageProfileService.RemoveProfileImageAsync(userId, cancellationToken);

            return result.IsSuccess ? Ok("Deleted successfully") : BadRequest(result.Error);
        }

    }
}
