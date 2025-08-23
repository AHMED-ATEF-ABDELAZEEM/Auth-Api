using Auth_Api.CustomResult;

namespace Auth_Api.CustomErrors
{
    public class UserError
    {
        public static Error InvalidCredentials => new Error("User.InvalidCredentials", "Invalid Email Or Password");  

        public static Error DuplicatedEmail = new Error("User.DuplicatedEmail", "This Email Is Already Registered, Please Use Another Email.");

        public static Error EmailNotConfirmed = new Error("User.EmailNotConfirmed", "Your Email Is Not Confirmed, Please Confirm Your Email To Proceed.");

        public static Error InvalidCode = new Error("User.InvalidCode", "The Code You Entered Is Invalid, Please Try Again.");

        public static Error DuplicatedConfirmation = new Error("User.DuplicatedConfirmation", "You Have Already Confirmed Your Email, No Need To Confirm Again.");
    }
}
