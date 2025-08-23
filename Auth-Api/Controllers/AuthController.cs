using Auth_Api.Contracts.Auth.Requests;
using Auth_Api.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;


namespace Auth_Api.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> LogIn ([FromBody]LoginRequest request,CancellationToken cancellationToken)
        {
            var result = await _authService.GetTokenAsync(request.email,request.password, cancellationToken);

            return result.IsSuccess ? Ok(result.Value) : BadRequest(result.Error);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request, CancellationToken cancellationToken)
        {
            var result = await _authService.GetRefreshTokenAsync(request.token,request.RefreshToken, cancellationToken);

            return result.IsSuccess ? Ok(result.Value) : BadRequest(result.Error);
        }

        [HttpPost("revoke-refresh-token")]
        public async Task<IActionResult> RevokeRefreshToken([FromBody]RefreshTokenRequest Request, CancellationToken cancellationToken)
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


    }
}
