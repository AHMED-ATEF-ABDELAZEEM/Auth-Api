using Auth_Api.Consts;
using Auth_Api.CustomErrors;
using Auth_Api.CustomResult;
using Auth_Api.Persistence;
using Microsoft.AspNetCore.Hosting;

namespace Auth_Api.Services
{

    public interface IImageProfileService
    {
        Task<Result> UploadProfileImageAsync(string userId, IFormFile Image, CancellationToken cancellationToken = default);

        Task<Result> RemoveProfileImageAsync(string userId, CancellationToken cancellationToken = default);
    }
    public class ImageProfileService : IImageProfileService
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly string _imagesPath;
        private readonly ILogger<ImageProfileService> _logger;

        public ImageProfileService(AppDbContext context, IWebHostEnvironment webHostEnvironment, ILogger<ImageProfileService> logger)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
            _imagesPath = $"{_webHostEnvironment.ContentRootPath}/Data/ProfileImages";

            if (!Directory.Exists(_imagesPath))
            {
                Directory.CreateDirectory(_imagesPath);
            }

            _logger = logger;
        }

        public async Task<Result> RemoveProfileImageAsync(string userId, CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("Starting Remove profile image for user ID: {UserId}", userId);

            var user = await _context.Users.FindAsync(userId, cancellationToken);

            if (user.ImageProfile is null)
            {
                _logger.LogWarning("Remove profile image failed: User has no profile image for user ID: {UserId}", userId);
                return Result.Failure(ImageProfileError.NoProfileImage);
            }

            _logger.LogInformation("Remove Old Profile Image for user ID: {UserId}", userId);
            var path = Path.Combine(_imagesPath, user.ImageProfile);
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            user.ImageProfile = null;
            await _context.SaveChangesAsync(cancellationToken);
            _logger.LogInformation("Remove profile image successfully for user ID: {UserId}", userId);
            return Result.Success();

        }

        public async Task<Result> UploadProfileImageAsync(string userId, IFormFile Image, CancellationToken cancellationToken = default)
        {

            _logger.LogInformation("Starting Upload profile image for user ID: {UserId}", userId);


            if (Image.Length > ImageProfileSettings.MaxFileSizeInBytes)
            {
                _logger.LogWarning("Upload profile image failed: File size is too large for user ID: {UserId}", userId);
                return Result.Failure(ImageProfileError.ImageTooLarge);
            }

            using BinaryReader binaryReader = new(Image.OpenReadStream());
            var bytes = binaryReader.ReadBytes(2);
            var fileSequenceHex = BitConverter.ToString(bytes);
            if (!ImageProfileSettings.AllowedSignatures.Contains(fileSequenceHex, StringComparer.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Upload profile image failed: File type is not allowed for user ID: {UserId}", userId);
                return Result.Failure(ImageProfileError.InvalidExtension);
            }


            var user = await _context.Users.FindAsync(userId, cancellationToken);


            if (!string.IsNullOrEmpty(user.ImageProfile))
            {
                _logger.LogInformation("Remove Old Profile Image for user ID: {UserId}", userId);
                var oldPath = Path.Combine(_imagesPath, user.ImageProfile);
                if (File.Exists(oldPath))
                {
                    File.Delete(oldPath);
                }
            }

            var uniqueFileName = $"{Guid.NewGuid()}{Path.GetExtension(Image.FileName)}";
            var newPath = Path.Combine(_imagesPath, uniqueFileName);

            using (var stream = File.Create(newPath))
            {
                await Image.CopyToAsync(stream, cancellationToken);
            }

            user.ImageProfile = uniqueFileName;
            await _context.SaveChangesAsync(cancellationToken);

            var imageUrl = $"/ProfileImages/{uniqueFileName}";

            _logger.LogInformation("Profile image uploaded successfully for user ID: {UserId}", userId);

            return Result.Success();
        }


    }
}
