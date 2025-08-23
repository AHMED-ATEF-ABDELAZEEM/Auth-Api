namespace Auth_Api.Contracts.Auth.Requests
{
    public class ConfirmEmailRequest
    {
        public string UserId { get; set; }
        public string Code { get; set; }
    }
}
