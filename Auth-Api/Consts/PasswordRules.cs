namespace Auth_Api.Consts
{
    public static class PasswordRules
    {
        public const string PasswordPattern = "(?=(.*[0-9]))(?=.*[\\!@#$%^&*()\\\\[\\]{}\\-_+=~`|:;\"'<>,./?])(?=.*[a-z])(?=(.*[A-Z]))(?=(.*)).{8,}";

        public const string PasswordErrorMessage = "Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character. It must match the pattern.";
    }
}
