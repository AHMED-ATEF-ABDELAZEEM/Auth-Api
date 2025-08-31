using Auth_Api.Contracts.Account.Requests;
using Auth_Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using System.Security.Claims;

namespace Auth_Api.Controllers
{
    [Route("me")]
    [ApiController]
    [Authorize]
    public class AccountsController : ControllerBase
    {
        private readonly IAccountService _accountService;

        public AccountsController(IAccountService accountService)
        {
            _accountService = accountService;
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
            var result = await _accountService.ChangePasswordAsync(userId!, request);

            return result.IsSuccess ? NoContent() : BadRequest(result.Error);

        }
    }
}
