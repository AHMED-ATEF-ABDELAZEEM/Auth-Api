using Auth_Api.Contracts.Account.Responses;
using Auth_Api.Contracts.Auth.Requests;
using Auth_Api.Models;
using Mapster;

namespace Auth_Api.Mapping
{
    public class MappingConfigurations : IRegister
    {
        public void Register(TypeAdapterConfig config)
        {

            // You Make Manual Mapping  Property Name Is Different

            config.NewConfig<RegisterRequest,ApplicationUser>()
                .Map(dest => dest.UserName, src => src.Email);

            config.NewConfig< ApplicationUser,UserProfileResponse>()
                .Map(dest => dest.HasPassword, src => src.PasswordHash != null);
        }
    }
}
