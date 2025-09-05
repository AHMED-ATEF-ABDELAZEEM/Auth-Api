namespace Auth_Api.Contracts.Account.Requests
{
    public class TwoFactorLoginRequest
    {
        public string SessionId { get; set; }
        public string Code { get; set; }
    }

}
