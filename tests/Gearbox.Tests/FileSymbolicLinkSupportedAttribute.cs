namespace Gearbox.Tests
{
    /// <summary>
    /// Skips a test when Windows cannot create file symlinks without additional privileges.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method)]
    internal sealed class FileSymbolicLinkSupportedAttribute : ConditionBaseAttribute
    {
        private static readonly Lazy<bool> Supported = new Lazy<bool>(CheckSupport);

        public FileSymbolicLinkSupportedAttribute()
            : base(ConditionMode.Include)
        {
            this.IgnoreMessage = "Windows file symlink creation requires Developer Mode or symbolic-link privilege.";
        }

        public override string GroupName => nameof(FileSymbolicLinkSupportedAttribute);

        public override bool IsConditionMet => Supported.Value;

        private static bool CheckSupport()
        {
            if (!OperatingSystem.IsWindows())
            {
                return true;
            }

            string directory = Path.Combine(Path.GetTempPath(), "Gearbox.FileSymlinkProbe." + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string link = Path.Combine(directory, "link.txt");
            try
            {
                // Symlink targets need not exist; only creation capability is probed.
                File.CreateSymbolicLink(link, Path.Combine(directory, "target.txt"));
                return true;
            }
            catch (IOException exception) when (exception.HResult == unchecked((int)0x80070522))
            {
                // HRESULT_FROM_WIN32(ERROR_PRIVILEGE_NOT_HELD). Other errors propagate.
                return false;
            }
            finally
            {
                File.Delete(link);
                Directory.Delete(directory);
            }
        }
    }
}
