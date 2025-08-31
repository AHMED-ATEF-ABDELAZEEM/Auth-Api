using Auth_Api.Consts;
using Auth_Api.Contracts.Account.Requests;
using FluentValidation;

namespace Auth_Api.Contracts.Account.Validations
{
    public class SetPasswordRequestValidator : AbstractValidator<SetPasswordRequest>
    {
        public SetPasswordRequestValidator()
        {
            RuleFor(x => x.Password)
                .NotEmpty()
                .Matches(PasswordRules.PasswordPattern)
                .WithMessage(PasswordRules.PasswordErrorMessage);

        }
    }
}
