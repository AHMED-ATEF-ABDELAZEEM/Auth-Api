using Auth_Api.Consts;
using Auth_Api.Contracts.Account.Requests;
using Auth_Api.Contracts.Auth.Requests;
using Auth_Api.Models;
using Auth_Api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;


namespace Auth_Api.Controllers
{
    [Route("[controller]")]
    [ApiController]
    [EnableRateLimiting(RateLimiters.IpLimit)]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AuthController(IAuthService authService, SignInManager<ApplicationUser> signInManager)
        {
            _authService = authService;
            _signInManager = signInManager;
        }

        [HttpPost("login")]
        public async Task<IActionResult> LogIn([FromBody] LoginRequest request, CancellationToken cancellationToken)
        {
            var result = await _authService.LoginAsync(request.email, request.password, cancellationToken);

            return result.IsSuccess ? Ok(result.Value) : BadRequest(result.Error);
        }

        [HttpPost("2fa/complete")]
        public async Task<IActionResult> CompleteTwoFactorLogin([FromBody] TwoFactorLoginRequest request)
        {
            var result = await _authService.CompleteTwoFactorLoginAsync(request.SessionId, request.Code);

            return result.IsSuccess ? Ok(result.Value) : BadRequest(result.Error);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request, CancellationToken cancellationToken)
        {
            var result = await _authService.GetRefreshTokenAsync(request.token, request.RefreshToken, cancellationToken);

            return result.IsSuccess ? Ok(result.Value) : BadRequest(result.Error);
        }

        [HttpPost("revoke-refresh-token")]
        public async Task<IActionResult> RevokeRefreshToken([FromBody] RefreshTokenRequest Request, CancellationToken cancellationToken)
        {
            var result = await _authService.RevokeRefreshTokenAsync(Request.token, Request.RefreshToken, cancellationToken);

            return result.IsSuccess ? NoContent() : BadRequest(result.Error);
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
        {
            var result = await _authService.RegisterAsync(request, cancellationToken);

            return result.IsSuccess ? Ok() : BadRequest(result.Error);
        }

        [HttpPost("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest request)
        {
            var result = await _authService.ConfirmEmailAsync(request);

            return result.IsSuccess ? Ok() : BadRequest(result.Error);
        }

        [HttpPost("resend-confirmation-email")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequest request, CancellationToken cancellationToken)
        {
            var result = await _authService.ResendConfirmationEmailAsync(request);
            return result.IsSuccess ? Ok() : BadRequest(result.Error);
        }



        [HttpPost("forget-password")]
        public async Task<IActionResult> ForgetPassword([FromBody] ForgetPasswordRequest request, CancellationToken cancellationToken)
        {
            var result = await _authService.SendResetPasswordEmailAsync(request.Email);

            return result.IsSuccess ? Ok() : BadRequest(result.Error);
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request, CancellationToken cancellationToken)
        {
            var result = await _authService.ResetPasswordAsync(request);

            return result.IsSuccess ? Ok() : BadRequest(result.Error);
        }



        [HttpGet("google")]
        [AllowAnonymous]
        public IActionResult GoogleLogin([FromQuery] string? returnUrl = null)
        {
            var redirectUrl = Url.ActionLink(nameof(GoogleLoginCallback), values: new { returnUrl });
            var props = _signInManager.ConfigureExternalAuthenticationProperties(GoogleDefaults.AuthenticationScheme, redirectUrl);
            return Challenge(props, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("signin-google")]
        public async Task<IActionResult> GoogleLoginCallback([FromQuery] string? returnUrl = null)
        {
            var result = await _authService.GoogleLoginAsync(HttpContext);
            return result.IsSuccess ? Ok(result.Value) : BadRequest(result.Error);
        }

    }
}

