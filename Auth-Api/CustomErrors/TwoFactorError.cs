using Auth_Api.CustomResult;

namespace Auth_Api.CustomErrors
{
    public class TwoFactorError
    {
        public static Error AlreadyEnabled = new Error(
            "TwoFactor.AlreadyEnabled",
            "Two-factor authentication is already enabled for your account."
        );

        public static Error InvalidCode = new Error(
            "TwoFactor.InvalidCode",
            "The code you entered is invalid. Please try again."
        );

        public static Error InvalidSession = new Error(
            "TwoFactor.InvalidSession",
            "The 2FA session is invalid or expired."
        );

        public static Error AlreadyDisabled = new Error(
            "TwoFactor.AlreadyDisabled",
            "Two-factor authentication is already disabled for your account."
        );
    }
}
