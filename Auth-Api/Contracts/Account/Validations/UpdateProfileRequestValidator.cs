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
}
