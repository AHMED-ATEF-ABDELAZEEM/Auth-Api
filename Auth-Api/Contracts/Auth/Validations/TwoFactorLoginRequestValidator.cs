using Auth_Api.Contracts.Account.Requests;
using FluentValidation;

namespace Auth_Api.Contracts.Auth.Validations
{
    public class TwoFactorLoginRequestValidator : AbstractValidator<TwoFactorLoginRequest>
    {
        public TwoFactorLoginRequestValidator()
        {
            RuleFor(x => x.SessionId)
                .NotEmpty()
                .NotNull();


            RuleFor(x => x.Code)
                .NotEmpty()
                .NotNull()
                .Length(6);
        }
    }



}
