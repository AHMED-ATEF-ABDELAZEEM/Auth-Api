using Auth_Api.Consts;
using Auth_Api.CustomResult;

namespace Auth_Api.CustomErrors
{
    public class ImageProfileError
    {
        public static Error ImageTooLarge => new Error("Image.TooLarge", $"Image is too large to upload, max size is {ImageProfileSettings.MaxFileSizeInMB} MB");

        public static Error InvalidExtension => new Error("Image.InvalidExtension", $"Invalid image extension,Only Extension Allowed are {String.Join(", ", ImageProfileSettings.AllowedExtensions)}");

    }
}
