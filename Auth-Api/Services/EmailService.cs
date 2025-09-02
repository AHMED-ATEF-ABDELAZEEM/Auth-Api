using Auth_Api.EmailSettings;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Auth_Api.Services
{
    public class EmailService : IEmailSender
    {
        private readonly MailSettings _emailSettings;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IOptions<MailSettings> emailSettings, ILogger<EmailService> logger)
        {
            _emailSettings = emailSettings.Value;
            _logger = logger;
        }
        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {

            var message = new MimeMessage
            {
                Sender = MailboxAddress.Parse(_emailSettings.Email),
                Subject = subject,
            };


            message.To.Add(MailboxAddress.Parse(email));

            var builder = new BodyBuilder
            {
                HtmlBody = htmlMessage
            };

            message.Body = builder.ToMessageBody();

            var smtp = new SmtpClient();
            smtp.Connect(_emailSettings.Host, _emailSettings.Port, SecureSocketOptions.StartTls);
            smtp.Authenticate(_emailSettings.Email, _emailSettings.Password);
            await smtp.SendAsync(message);
            smtp.Disconnect(true);
        }
    }
}
