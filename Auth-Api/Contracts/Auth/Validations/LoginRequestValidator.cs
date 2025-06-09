using Auth_Api.Contracts.Auth.Requests;
using FluentValidation;

namespace Auth_Api.Contracts.Auth.Validations
{
    public class LoginRequestValidator : AbstractValidator<LoginRequest>
    {
        public LoginRequestValidator()
        {
            RuleFor(x => x.email)
                .NotEmpty()
                .EmailAddress();

            RuleFor(x => x.password)
                .NotEmpty()
                .Length(5, 25);

        }
    }
}
