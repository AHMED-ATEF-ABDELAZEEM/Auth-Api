using Auth_Api.Contracts.Account.Requests;
using FluentValidation;

namespace Auth_Api.Contracts.Account.Validations
{
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
