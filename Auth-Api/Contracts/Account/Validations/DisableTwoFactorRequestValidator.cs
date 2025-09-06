using Auth_Api.Contracts.Account.Requests;
using FluentValidation;

namespace Auth_Api.Contracts.Account.Validations
{
    public class DisableTwoFactorRequestValidator : AbstractValidator<DisableTwoFactorRequest>
    {
        public DisableTwoFactorRequestValidator()
        {
            RuleFor(x => x.Code)
                .NotEmpty()
                .NotNull()
                .Length(6);

        }
    }



}
