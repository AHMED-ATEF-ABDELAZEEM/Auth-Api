
using Auth_Api.Authentication;
using Auth_Api.Consts;
using Auth_Api.CustomErrors;
using Auth_Api.EmailSettings;
using Auth_Api.Models;
using Auth_Api.Persistence;
using Auth_Api.SeedingData;
using Auth_Api.Services;
using FluentValidation;
using Mapster;
using MapsterMapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Connections.Abstractions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using SharpGrip.FluentValidation.AutoValidation.Mvc.Extensions;
using System.Reflection;
using System.Text;
using System.Threading.RateLimiting;

namespace Auth_Api
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddOpenApi();

            // Add Mapster
            var MappingConfig = TypeAdapterConfig.GlobalSettings;
            MappingConfig.Scan(Assembly.GetExecutingAssembly());
            builder.Services.AddSingleton<IMapper>(new Mapper(MappingConfig));


            // fluent validation
            builder.Services.AddValidatorsFromAssembly(Assembly.GetExecutingAssembly());
            builder.Services.AddFluentValidationAutoValidation();

            builder.Services.AddDbContext<AppDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("connectionString")));
                

            builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

            builder.Services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequiredLength = 8;
                options.SignIn.RequireConfirmedEmail = true;
                options.User.RequireUniqueEmail = true;
            });


            builder.Services.AddSingleton<IJwtProvider, JwtProvider>();
            builder.Services.AddScoped<IAuthService, AuthService>();
            builder.Services.AddScoped<IEmailSender, EmailService>();
            builder.Services.AddScoped<IAccountService, AccountService>();
            builder.Services.AddTransient<AppDbSeeder>();

            builder.Services.AddHttpContextAccessor();

            builder.Services.Configure<MailSettings>(builder.Configuration.GetSection(nameof(MailSettings)));

            builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("JWT"));

            var JwtSetting = builder.Configuration.GetSection("JWT").Get<JwtOptions>();


            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSetting!.Key)),
                    ValidIssuer = JwtSetting.Issuer,
                    ValidAudience = JwtSetting.Audience,

                };
            })
            .AddGoogle(options =>
            {
                options.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
                options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
            });

            // Rate Limiter
            builder.Services.AddRateLimiter(rateLimiterOptions =>
            {
                rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

                rateLimiterOptions.AddPolicy(policyName: RateLimiters.IpLimit, httpContext =>
                    RateLimitPartition.GetFixedWindowLimiter<string>(
                        partitionKey: httpContext.Connection.RemoteIpAddress?.ToString()!,
                        factory: partition => new FixedWindowRateLimiterOptions
                        {
                            AutoReplenishment = true,
                            PermitLimit = 20,
                            Window = TimeSpan.FromMinutes(1)
                        }

                    )
                );

                rateLimiterOptions.AddPolicy(policyName: RateLimiters.UserLimit, httpContext =>
                    RateLimitPartition.GetFixedWindowLimiter<string>(
                        partitionKey: httpContext.User.Identity?.Name?.ToString()!,
                        factory: partition => new FixedWindowRateLimiterOptions
                        {
                            AutoReplenishment = true,
                            PermitLimit = 100,
                            Window = TimeSpan.FromMinutes(1)
                        }

                    )
                );

                rateLimiterOptions.AddConcurrencyLimiter(policyName: RateLimiters.ConcurrencyLimit, options =>
                {
                    options.PermitLimit = 1000;
                    options.QueueLimit = 100;
                    options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                });

            });

            // Exception Handler
            builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
            builder.Services.AddProblemDetails();

            // To Use Serilog Package For Logging
            builder.Host.UseSerilog((context, configuration) => 
            {
                // Read Configuration from appsettings.json
                configuration.ReadFrom.Configuration(context.Configuration);

            });

            var app = builder.Build();

            using (var scope =  app.Services.CreateScope())
            {
                var seeder = scope.ServiceProvider.GetRequiredService<AppDbSeeder>();
                seeder.SeedAsync().GetAwaiter().GetResult(); ;
            }

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }


            app.UseSerilogRequestLogging();

            app.UseHttpsRedirection();

            app.UseRateLimiter();

            app.UseAuthentication();

            app.UseAuthorization();

            app.MapControllers();

            app.UseExceptionHandler();

            app.Run();
        }
    }
}



