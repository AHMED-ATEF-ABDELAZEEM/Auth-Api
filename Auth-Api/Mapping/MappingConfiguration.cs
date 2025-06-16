using Mapster;

namespace Auth_Api.Mapping
{
    public class MappingConfigurations : IRegister
    {
        public void Register(TypeAdapterConfig config)
        {

            // You Make Manual Mapping  Property Name Is Different

            //config.NewConfig<Poll,PollResponse>()
            //    .Map(dest => dest.description, src => src.Summary);
        }
    }
}
