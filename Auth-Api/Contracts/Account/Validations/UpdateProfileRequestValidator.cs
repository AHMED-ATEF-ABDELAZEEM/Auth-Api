using Auth_Api.Consts;
using Auth_Api.Contracts.Account.Requests;
using FluentValidation;

namespace Auth_Api.Contracts.Account.Validations
{
    public class UpdateProfileRequestValidator : AbstractValidator<UpdateProfileRequest>
    {
        public UpdateProfileRequestValidator()
        {
            RuleFor(x => x.FirstName)
                .NotEmpty()
                .Length(3, 50).WithMessage("First name must be between 3 and 50 characters long.");

            RuleFor(x => x.LastName)
                .NotEmpty().WithMessage("Last name is required.")
                .Length(3, 50).WithMessage("Last name must be between 3 and 50 characters long.");
        }
    }

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
}
