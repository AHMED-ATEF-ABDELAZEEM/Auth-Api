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
                .NotEmpty()
                .Matches("(?=(.*[0-9]))(?=.*[\\!@#$%^&*()\\\\[\\]{}\\-_+=~`|:;\"'<>,./?])(?=.*[a-z])(?=(.*[A-Z]))(?=(.*)).{8,}")
                .WithMessage("Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character. It must match the pattern");


            RuleFor(x => x.FirstName)
                .NotEmpty()
                .Length(3, 100);
            RuleFor(x => x.LastName)
                .NotEmpty()
                .Length(3, 100);

        }
    }
}
