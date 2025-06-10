using Auth_Api.Contracts.Auth.Requests;
using FluentValidation;

namespace Auth_Api.Contracts.Auth.Validations
{
    public class RefreshTokenRequestValidator : AbstractValidator<RefreshTokenRequest>
    {
        public RefreshTokenRequestValidator()
        {
            RuleFor(x => x.token)
                .NotEmpty()
                .MinimumLength(30);

            RuleFor(x => x.RefreshToken)
                .NotEmpty()
                .MinimumLength(20);
        }
    }
}
