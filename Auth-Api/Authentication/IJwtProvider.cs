using Auth_Api.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace Auth_Api.Authentication
{
    public class TokenInformation
    {
        public string Token { get; set; }
        public int ExpiresIn { get; set; }
    }
    public interface IJwtProvider
    {
        TokenInformation GenerateToken(ApplicationUser User, IEnumerable<string> roles);

        string? ValidateToken(string token);
    }
    public class JwtProvider : IJwtProvider
    {
        private readonly JwtOptions _JwtOptions;

        public JwtProvider(IOptions<JwtOptions> JwtOptions)
        {
            _JwtOptions = JwtOptions.Value;
        }
        public TokenInformation GenerateToken(ApplicationUser User,IEnumerable<string> roles)
        {
            var Claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,User.Id),
                new Claim(JwtRegisteredClaimNames.Email,User.Email!),
                new Claim(JwtRegisteredClaimNames.GivenName,User.FirstName),
                new Claim(JwtRegisteredClaimNames.FamilyName,User.LastName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(nameof(roles), JsonSerializer.Serialize(roles), JsonClaimValueTypes.JsonArray),
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

        public string? ValidateToken(string token)
        {
            var TokenHandler = new JwtSecurityTokenHandler();
            var SymmetricKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_JwtOptions.Key));
            try
            {
                TokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    IssuerSigningKey = SymmetricKey,
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero,
                }, out SecurityToken validatedToken);

                var JwtToken = (JwtSecurityToken)validatedToken;
                var UserId = JwtToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub)?.Value;
                return UserId;
            }
            catch
            {
                return null;
            }

        }
    }
}
