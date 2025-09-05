namespace Auth_Api.Contracts.Auth.Responses
{
    public class LoginResponse
    {
        public bool RequiresTwoFactor { get; set; }
        public string? SessionId { get; set; }
        public AuthResponse? AuthResponse { get; set; }
    }
}
