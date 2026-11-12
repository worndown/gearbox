using System.Diagnostics;

namespace Gearbox
{
    /// <summary>
    /// Base class for running executables and reading output.
    /// </summary>
    public class Executable
    {
        /// <summary>
        /// Path to executable.
        /// </summary>
        private readonly string executable;

        /// <summary>
        /// Standard output goes here.
        /// </summary>
        private readonly List<string> output = new List<string>();

        /// <summary>
        /// Standard error goes here.
        /// </summary>
        private readonly List<string> error = new List<string>();

        /// <summary>
        /// Initializes a new instance of the Executable class.
        /// </summary>
        /// <param name="executable">Executable name or path.</param>
        /// <param name="resolve">Resolve executable full path.</param>
        public Executable(string executable, bool resolve)
        {
            ArgumentException.ThrowIfNullOrEmpty(executable);

            if (resolve)
            {
                string? resolvedPath = FindFileInPath(executable);
                this.executable = resolvedPath ?? throw new FileNotFoundException($"Executable \"{executable}\" was not found in path.");
            }
            else
            {
                this.executable = executable;
            }
        }

        /// <summary>
        /// Gets executable standard output.
        /// </summary>
        public IList<string> Output => this.output.AsReadOnly();

        /// <summary>
        /// Gets executable standard error.
        /// </summary>
        public IList<string> Error => this.error.AsReadOnly();

        /// <summary>
        /// Runs executable and waiting for it to return.
        /// </summary>
        /// <returns>Process exit code.</returns>
        public int Run()
        {
            return this.Run(null);
        }

        /// <summary>
        /// Runs executable with specified arguments and waits for it to return.
        /// </summary>
        /// <param name="arguments">Cmdline arguments to executable.</param>
        /// <returns>Process exit code.</returns>
        public int Run(string? arguments)
        {
            return this.Run(arguments, int.MaxValue);
        }

        /// <summary>
        /// Runs executable with specified arguments and waits for it to return.
        /// </summary>
        /// <param name="arguments">Cmdline argument to the executable.</param>
        /// <param name="timeout">Timeout in milliseconds.</param>
        /// <returns>Process exit code.</returns>
        public int Run(string? arguments, int timeout)
        {
            this.output.Clear();
            this.error.Clear();

            using (Process process = new Process())
            {
                process.StartInfo.FileName = this.executable;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.RedirectStandardOutput = true;

                if (arguments != null)
                {
                    process.StartInfo.Arguments = arguments;
                }

                process.OutputDataReceived += this.OnOutputDataReceived;
                process.ErrorDataReceived += this.OnErrorDataReceived;

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                process.WaitForExit(timeout);
                return process.ExitCode;
            }
        }

        /// <summary>
        /// Called each time an application writes a line to its redirected standard output stream.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event data.</param>
        private void OnOutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (!string.IsNullOrEmpty(e.Data))
            {
                this.output.Add(e.Data);
            }
        }

        /// <summary>
        /// Called when application writes to its redirected standard error stream.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event data.</param>
        private void OnErrorDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (!string.IsNullOrEmpty(e.Data))
            {
                this.error.Add(e.Data);
            }
        }

        /// <summary>
        /// Searching for the specified file in path.
        /// </summary>
        /// <param name="filename">File to find.</param>
        /// <returns>Full path to the file, if found; null otherwise.</returns>
        private static string? FindFileInPath(string filename)
        {
            if (File.Exists(filename))
            {
                return Path.GetFullPath(filename);
            }

            string? pathValue = Environment.GetEnvironmentVariable("PATH");
            if (pathValue != null)
            {
                foreach (string path in pathValue.Split([';'], StringSplitOptions.RemoveEmptyEntries))
                {
                    string fullPath = Path.Combine(path, filename);
                    if (File.Exists(fullPath))
                    {
                        return fullPath;
                    }
                }
            }

            return null;
        }
    }
}
