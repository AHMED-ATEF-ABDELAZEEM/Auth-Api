namespace Auth_Api.Contracts.Auth.Requests
{
    public class RefreshTokenRequest
    {
        public string token { get; set; }
        public string RefreshToken { get; set; }
    }
}
