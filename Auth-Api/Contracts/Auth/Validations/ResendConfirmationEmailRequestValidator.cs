using Auth_Api.Contracts.Auth.Requests;
using FluentValidation;

namespace Auth_Api.Contracts.Auth.Validations
{
    public class ResendConfirmationEmailRequestValidator : AbstractValidator<ResendConfirmationEmailRequest>
    {
        public ResendConfirmationEmailRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress();

        }
    }
}
