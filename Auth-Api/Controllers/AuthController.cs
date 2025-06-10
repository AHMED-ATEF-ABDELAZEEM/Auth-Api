using Auth_Api.Contracts.Auth.Requests;
using Auth_Api.Services;
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
        public async Task<IActionResult> LogInAsync ([FromBody]LoginRequest request,CancellationToken cancellationToken)
        {
            var result = await _authService.GetTokenAsync(request.email,request.password, cancellationToken);
            if (result == null) return BadRequest("Invalid Email or Password");
            return Ok(result);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshTokenAsync([FromBody] RefreshTokenRequest request, CancellationToken cancellationToken)
        {
            var result = await _authService.GetRefreshTokenAsync(request.token,request.RefreshToken, cancellationToken);
            if (result == null) return BadRequest("Token Or Refresh Token Is Not Valid");
            return Ok(result);
        }

    }
}
