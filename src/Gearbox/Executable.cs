using System.Diagnostics;

namespace Gearbox
{
    /// <summary>
    /// Base class for running executables and reading output.
    /// </summary>
    /// <remarks>
    /// An instance supports one run at a time, across Run and RunAsync.
    /// Read Output and Error after the run completes, including asynchronous cancellation cleanup.
    /// Results are read-only live views, replaced by each valid run, including a failed launch.
    /// Arguments use the operating system's command-line quoting rules; no shell is invoked.
    /// The child inherits the current working directory, environment, and default stream encodings.
    /// </remarks>
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
        /// <exception cref="ArgumentNullException">Executable is null.</exception>
        /// <exception cref="ArgumentException">Executable is empty.</exception>
        /// <exception cref="FileNotFoundException">Resolution is requested but no file is found.</exception>
        /// <remarks>
        /// Resolution checks the supplied path before PATH entries, in order. On Windows,
        /// extensionless inputs also try .exe. Resolved paths are fixed at construction time.
        /// Without resolution, executable lookup is delegated to Process.Start at run time.
        /// </remarks>
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
        /// <remarks>Read-only live view of the latest run, including blank lines and partial output on timeout or cancellation.</remarks>
        public IList<string> Output => this.output.AsReadOnly();

        /// <summary>
        /// Gets executable standard error.
        /// </summary>
        /// <remarks>Read-only live view of the latest run, including blank lines and partial output on timeout or cancellation.</remarks>
        public IList<string> Error => this.error.AsReadOnly();

        /// <summary>
        /// Runs executable without a timeout and waits for it and its output readers to finish.
        /// </summary>
        /// <returns>Process exit code.</returns>
        public int Run()
        {
            return this.Run(null);
        }

        /// <summary>
        /// Runs executable without a timeout and waits for it and its output readers to finish.
        /// </summary>
        /// <param name="arguments">Cmdline arguments to executable.</param>
        /// <returns>Process exit code.</returns>
        public int Run(string? arguments)
        {
            return this.Run(arguments, Timeout.Infinite);
        }

        /// <summary>
        /// Runs executable with specified arguments and waits for it and its output readers to finish.
        /// </summary>
        /// <param name="arguments">Cmdline argument to the executable.</param>
        /// <param name="timeout">Process exit timeout in milliseconds; -1 waits indefinitely, and 0 checks immediately.</param>
        /// <returns>Process exit code.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Timeout is less than -1. Previous results are preserved.</exception>
        /// <exception cref="TimeoutException">The process timed out; its process tree was terminated and partial output retained.</exception>
        /// <remarks>
        /// The timeout covers waiting for process exit. Draining output and timeout cleanup
        /// may take additional time. Process launch and cleanup failures propagate to the caller.
        /// </remarks>
        public int Run(string? arguments, int timeout)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(timeout, Timeout.Infinite);

            this.output.Clear();
            this.error.Clear();

            using (Process process = this.CreateProcess(arguments))
            {
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                if (!process.WaitForExit(timeout))
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit();
                    throw new TimeoutException($"Executable \"{this.executable}\" did not exit within {timeout} milliseconds.");
                }

                // A finite wait only observes process exit; this also drains the async readers.
                process.WaitForExit();
                return process.ExitCode;
            }
        }

        /// <summary>
        /// Runs executable asynchronously and waits for it and its output readers to finish.
        /// </summary>
        /// <param name="arguments">Command-line arguments to the executable.</param>
        /// <param name="timeout">Process exit timeout in milliseconds; -1 waits indefinitely, and 0 checks immediately.</param>
        /// <param name="cancellationToken">Cancels the run and terminates its process tree.</param>
        /// <returns>A task returning the process exit code after output capture finishes.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Timeout is less than -1. Previous results are preserved.</exception>
        /// <exception cref="TimeoutException">The process timed out; its process tree was terminated and partial output retained.</exception>
        /// <exception cref="OperationCanceledException">Cancellation was requested. A started process tree was terminated and partial output retained.</exception>
        /// <remarks>
        /// Timeout validation is synchronous. A token already canceled prevents launch and preserves
        /// previous results. The timeout covers process exit; cancellation also covers output draining.
        /// Termination and output cleanup finish before the task completes and may take additional time.
        /// Process launch and cleanup failures propagate to the caller.
        /// </remarks>
        public Task<int> RunAsync(string? arguments = null, int timeout = Timeout.Infinite, CancellationToken cancellationToken = default)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(timeout, Timeout.Infinite);
            return this.RunAsyncCore(arguments, timeout, cancellationToken);
        }

        private async Task<int> RunAsyncCore(string? arguments, int timeout, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.output.Clear();
            this.error.Clear();

            using Process process = this.CreateProcess(arguments);
            TaskCompletionSource exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            process.Exited += (_, _) => exited.TrySetResult();
            process.EnableRaisingEvents = true;
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            try
            {
                // WaitForExitAsync also drains readers, so time only native process exit here.
                if (!process.HasExited)
                {
                    try
                    {
                        await exited.Task.WaitAsync(TimeSpan.FromMilliseconds(timeout), cancellationToken).ConfigureAwait(false);
                    }
                    catch (TimeoutException) when (process.HasExited)
                    {
                        // Exit notifications can be delayed after the native process has exited.
                    }
                }

                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                return process.ExitCode;
            }
            catch (TimeoutException exception)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync().ConfigureAwait(false);
                throw new TimeoutException($"Executable \"{this.executable}\" did not exit within {timeout} milliseconds.", exception);
            }
            catch (OperationCanceledException)
            {
                process.Kill(entireProcessTree: true);
                // Cleanup must finish even though the caller's token has been canceled.
                await process.WaitForExitAsync().ConfigureAwait(false);
                throw;
            }
        }

        private Process CreateProcess(string? arguments)
        {
            Process process = new Process();
            process.StartInfo.FileName = this.executable;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.Arguments = arguments ?? string.Empty;
            process.OutputDataReceived += this.OnOutputDataReceived;
            process.ErrorDataReceived += this.OnErrorDataReceived;
            return process;
        }

        /// <summary>
        /// Called each time an application writes a line to its redirected standard output stream.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event data.</param>
        private void OnOutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
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
            if (e.Data != null)
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
            string? directPath = FindFile(filename);
            if (directPath != null)
            {
                return directPath;
            }

            string? pathValue = Environment.GetEnvironmentVariable("PATH");
            if (pathValue != null)
            {
                foreach (string path in pathValue.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
                {
                    string? fullPath = FindFile(Path.Combine(path, filename));
                    if (fullPath != null)
                    {
                        return fullPath;
                    }
                }
            }

            return null;
        }

        private static string? FindFile(string filename)
        {
            if (File.Exists(filename))
            {
                return Path.GetFullPath(filename);
            }

            if (OperatingSystem.IsWindows() && !Path.HasExtension(filename) && File.Exists(filename + ".exe"))
            {
                return Path.GetFullPath(filename + ".exe");
            }

            return null;
        }
    }
}
