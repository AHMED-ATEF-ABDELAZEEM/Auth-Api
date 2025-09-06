using Auth_Api.CustomResult;

namespace Auth_Api.CustomErrors
{
    public static class ExternalAuthError
    {
        public static Error AuthenticationFailed = new Error(
            "ExternalAuth.AuthenticationFailed",
            "External authentication failed. Please try again."
        );

        public static  Error UserEmailNotFound = new Error(
            "ExternalAuth.UserEmailNotFound",
            "User email not found in external provider claims."
            );

        public static  Error UserEmailNotVerified = new Error(
            "ExternalAuth.UserEmailNotVerified",
            "Your Google account email is not verified. Please verify your email in Google account settings before logging in."
            );
    }
}
