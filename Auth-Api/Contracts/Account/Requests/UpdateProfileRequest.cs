namespace Auth_Api.Contracts.Account.Requests
{
    public class UpdateProfileRequest
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }

    public class EnableTwoFactorRequest
    {
        public string Code { get; set; }
    }

}
