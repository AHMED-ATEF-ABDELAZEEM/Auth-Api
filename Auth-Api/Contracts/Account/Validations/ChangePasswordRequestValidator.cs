using Auth_Api.Consts;
using Auth_Api.Contracts.Account.Requests;
using FluentValidation;

namespace Auth_Api.Contracts.Account.Validations
{
    public class ChangePasswordRequestValidator : AbstractValidator<ChangePasswordRequest>
    {
        public ChangePasswordRequestValidator()
        {
            RuleFor(x => x.currentPassword)
                .NotEmpty()
                .Matches(PasswordRules.PasswordPattern)
                .WithMessage(PasswordRules.PasswordErrorMessage);

            RuleFor(x => x.newPassword)
                .NotEmpty()
                .Matches(PasswordRules.PasswordPattern)
                .WithMessage(PasswordRules.PasswordErrorMessage);

            RuleFor(x => x)
                .Must(x => x.newPassword != x.currentPassword)
                .WithMessage("New password must be different from the current password.");
        }
    }

    public class EnableTwoFactorRequestValidator : AbstractValidator<EnableTwoFactorRequest>
    {
        public EnableTwoFactorRequestValidator()
        {
            RuleFor(x => x.Code)
                .NotEmpty()
                .NotNull()
                .Length(6);
        }
    }
}
