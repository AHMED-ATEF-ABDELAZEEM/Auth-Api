using Auth_Api.CustomResult;

namespace Auth_Api.CustomErrors
{
    public class UserError
    {
        public static Error InvalidCredentials => new Error("User.InvalidCredentials", "Invalid Email Or Password");
    }
}
