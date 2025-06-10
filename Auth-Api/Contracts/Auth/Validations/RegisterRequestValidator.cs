using Auth_Api.Contracts.Auth.Requests;
using FluentValidation;

namespace Auth_Api.Contracts.Auth.Validations
{
    public class RegisterRequestValidator : AbstractValidator<RegisterRequest>
    {
        public RegisterRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress();

            RuleFor(x => x.Password)
                .NotEmpty();

            RuleFor(x => x.FirstName)
                .NotEmpty()
                .Length(3, 25);
            RuleFor(x => x.LastName)
                .NotEmpty()
                .Length(3, 25);

        }
    }
}
