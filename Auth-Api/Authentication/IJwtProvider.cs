using Auth_Api.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Auth_Api.Authentication
{
    public class TokenInformation
    {
        public string Token { get; set; }
        public int ExpiresIn { get; set; }
    }
    public interface IJwtProvider
    {
        TokenInformation GenerateToken(ApplicationUser User);
    }
    public class JwtProvider : IJwtProvider
    {
        private readonly JwtOptions _JwtOptions;

        public JwtProvider(IOptions<JwtOptions> JwtOptions)
        {
            _JwtOptions = JwtOptions.Value;
        }
        public TokenInformation GenerateToken(ApplicationUser User)
        {
            var Claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,User.Id),
                new Claim(JwtRegisteredClaimNames.Email,User.Email!),
                new Claim(JwtRegisteredClaimNames.GivenName,User.FirstName),
                new Claim(JwtRegisteredClaimNames.FamilyName,User.LastName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),

            };

            var SymmetricKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_JwtOptions.Key));

            var SigningCredentials = new SigningCredentials(SymmetricKey, SecurityAlgorithms.HmacSha256);


            var ExpiresMinute = _JwtOptions.ExpireTime;

            var SecurityToken = new JwtSecurityToken(
                issuer: _JwtOptions.Issuer,
                audience: _JwtOptions.Audience,
                claims: Claims,
                expires: DateTime.UtcNow.AddMinutes(ExpiresMinute),
                signingCredentials: SigningCredentials
            );


            return new TokenInformation
            {
                Token = new JwtSecurityTokenHandler().WriteToken(SecurityToken),
                ExpiresIn = ExpiresMinute,
            };
        }
    }
}
