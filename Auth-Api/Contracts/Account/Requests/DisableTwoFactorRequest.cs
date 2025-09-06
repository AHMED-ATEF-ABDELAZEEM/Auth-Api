namespace Auth_Api.Contracts.Account.Requests
{
    public class DisableTwoFactorRequest
    {
        public string Code { get; set; } = string.Empty;
    }

}
