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

        public static Error LockedOut = new("User.LockedOut", "Your account has been locked due to multiple failed login attempts. Please try again later.");

        public static Error ExternalLogin = new Error("User.ExternalLogin","This account is linked to an external provider. Please login using Google instead of email and password.");
    }

    public static class ExternalAuthError
    {
        public static Error AuthenticationFailed = new Error(
            "ExternalAuth.AuthenticationFailed",
            "External authentication failed. Please try again."
        );
    }
}
