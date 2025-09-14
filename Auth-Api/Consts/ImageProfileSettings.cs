namespace Auth_Api.Consts
{
    public static class ImageProfileSettings
    {
        public const int MaxFileSizeInMB = 1;
        public const int MaxFileSizeInBytes = MaxFileSizeInMB * 1024 * 1024;
        public static readonly string[] AllowedSignatures =
        {
            "FF-D8", // JPEG/JPG
            "89-50", // PNG
        };
        public static readonly string[] AllowedExtensions = { ".jpg", ".jpeg", ".png" };
        
    }
}
