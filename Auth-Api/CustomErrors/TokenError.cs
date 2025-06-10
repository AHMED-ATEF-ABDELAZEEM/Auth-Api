using Auth_Api.CustomResult;

namespace Auth_Api.CustomErrors
{
    public class TokenError
    {
        public static Error InvalidToken => new Error("Token.Invalid", "Invalid Token or Expired");
    }
}
