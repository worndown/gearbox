using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Gearbox.Tests
{
    [TestClass]
    public partial class ExecutableTests
    {
        private string? root = null;
        private string Root => this.root ?? throw new InvalidOperationException("The test fixture has not been initialized.");
        private string executableName = null!;
        private static string HelperDirectory => Path.Combine(AppContext.BaseDirectory, "test-process");
        private static string HelperName => "Gearbox.TestProcess" + (OperatingSystem.IsWindows() ? ".exe" : "");
        private static string HelperPath => Path.Combine(HelperDirectory, HelperName);

        [TestInitialize]
        public void Initialize()
        {
            Assert.IsTrue(File.Exists(HelperPath), "The test process and its runtime files must be built and copied beside the tests.");
            this.root = Path.Combine(Path.GetTempPath(), "Gearbox.ExecutableTests." + Guid.NewGuid().ToString("N"));
            this.executableName = "probe-" + Guid.NewGuid().ToString("N") + (OperatingSystem.IsWindows() ? ".exe" : "");
            Directory.CreateDirectory(this.Root);
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (this.root == null || !Directory.Exists(this.root))
            {
                return;
            }

            // Markers include start times so cleanup cannot target a reused process ID.
            foreach (string marker in Directory.EnumerateFiles(this.Root, "*.pid", SearchOption.AllDirectories))
            {
                using Process? process = GetMarkedProcess(marker);
                if (process != null)
                {
                    process.Kill(entireProcessTree: true);
                    Assert.IsTrue(process.WaitForExit(5000), "Test child cleanup did not finish.");
                }
            }

            Directory.Delete(this.Root, true);
        }

        [TestMethod]
        [DataRow(null, false)]
        [DataRow(null, true)]
        [DataRow("", false)]
        [DataRow("", true)]
        public void Constructor_NullOrEmpty_RejectsExecutable(string? filename, bool resolve)
        {
            ArgumentException exception = filename == null
                ? Assert.ThrowsExactly<ArgumentNullException>(() => new Executable(filename!, resolve))
                : Assert.ThrowsExactly<ArgumentException>(() => new Executable(filename, resolve));
            Assert.AreEqual("executable", exception.ParamName);
        }

        [TestMethod]
        public void Constructor_WithoutResolution_AcceptsMissingFileAndStartsWithEmptyReadOnlyResults()
        {
            Executable executable = new Executable(Path.Combine(this.Root, this.executableName), false);
            Assert.AreEqual(0, executable.Output.Count);
            Assert.AreEqual(0, executable.Error.Count);
            Assert.IsTrue(executable.Output.IsReadOnly);
            Assert.IsTrue(executable.Error.IsReadOnly);
            Assert.ThrowsExactly<Win32Exception>(() => executable.Run(null, 10000));
        }

        [TestMethod]
        [DoNotParallelize]
        [DataRow(false)]
        [DataRow(true)]
        public void Constructor_Resolution_FindsAbsoluteAndRelativeDirectFiles(bool relative)
        {
            string path = this.InstallHelper("tools with spaces");
            this.WithEnvironment(null, this.Root, () =>
            {
                string filename = relative ? Path.GetRelativePath(this.Root, path) : path;
                Executable executable = new Executable(filename, true);
                this.AssertIdentity(executable, path);
            });
        }

        [TestMethod]
        [DoNotParallelize]
        [DataRow(null)]
        [DataRow("")]
        public void Constructor_MissingOrEmptyPath_ReportsMissingNameButAllowsDirectFile(string? pathValue)
        {
            string path = this.InstallHelper("tools");
            this.WithEnvironment(pathValue, this.Root, () =>
            {
                FileNotFoundException exception = Assert.ThrowsExactly<FileNotFoundException>(
                    () => new Executable(this.executableName, true));
                StringAssert.Contains(exception.Message, this.executableName);
                this.AssertIdentity(new Executable(path, true), path);
            });
        }

        [TestMethod]
        [DoNotParallelize]
        [DataRow(false)]
        [DataRow(true)]
        public void Constructor_PathLookup_PreservesEntryOrderAndSkipsEmptyEntries(bool includeEmptyEntries)
        {
            string first = this.InstallHelper("first tools");
            string second = this.InstallHelper("second tools");
            string[] directories = [Path.Combine(this.Root, "missing"), Path.GetDirectoryName(first)!, Path.GetDirectoryName(second)!];
            string pathValue = string.Join(Path.PathSeparator, directories);
            if (includeEmptyEntries)
            {
                pathValue = Path.PathSeparator + pathValue + Path.PathSeparator + Path.PathSeparator;
            }

            this.WithEnvironment(pathValue, this.Root, () => this.AssertIdentity(new Executable(this.executableName, true), first));
        }

        [TestMethod]
        [DoNotParallelize]
        public void Constructor_DirectFile_TakesPrecedenceOverPath()
        {
            string direct = this.InstallHelper("current");
            string other = this.InstallHelper("path");
            this.WithEnvironment(Path.GetDirectoryName(other), Path.GetDirectoryName(direct)!, () =>
                this.AssertIdentity(new Executable(this.executableName, true), direct));
        }

        [TestMethod]
        [DoNotParallelize]
        [DataRow(false)]
        [DataRow(true)]
        public void Constructor_ResolvedFile_RemainsFixedAfterDirectoryAndPathChanges(bool fromPath)
        {
            string path = this.InstallHelper("relative tools");
            string otherDirectory = Path.Combine(this.Root, "other");
            Directory.CreateDirectory(otherDirectory);
            this.WithEnvironment(fromPath ? "relative tools" : null, this.Root, () =>
            {
                string filename = fromPath ? this.executableName : Path.GetRelativePath(this.Root, path);
                Executable executable = new Executable(filename, true);
                Directory.SetCurrentDirectory(otherDirectory);
                Environment.SetEnvironmentVariable("PATH", null);
                this.AssertIdentity(executable, path);
            });
        }

        [TestMethod]
        [DoNotParallelize]
        [DataRow(false)]
        [DataRow(true)]
        public void Constructor_WithoutResolution_UsesDirectoryOrPathAtRunTime(bool fromPath)
        {
            string path = this.InstallHelper("tools");
            string otherDirectory = Path.Combine(this.Root, "other");
            Directory.CreateDirectory(otherDirectory);
            this.WithEnvironment(null, otherDirectory, () =>
            {
                string filename = fromPath ? this.executableName : Path.Combine("tools", this.executableName);
                Executable executable = new Executable(filename, false);
                Directory.SetCurrentDirectory(this.Root);
                Environment.SetEnvironmentVariable("PATH", fromPath ? Path.GetDirectoryName(path) : null);
                this.AssertIdentity(executable, path);
            });
        }

        [TestMethod]
        [DoNotParallelize]
        [DataRow(false)]
        [DataRow(true)]
        public void Constructor_ExtensionlessInput_UsesExeFallbackOnlyOnWindows(bool fromPath)
        {
            string filename = "extensionless-probe.exe";
            string path = this.InstallHelper("tools", filename);
            string currentDirectory = fromPath ? this.Root : Path.GetDirectoryName(path)!;
            this.WithEnvironment(fromPath ? Path.GetDirectoryName(path) : null, currentDirectory, () =>
            {
                if (OperatingSystem.IsWindows())
                {
                    this.AssertIdentity(new Executable("extensionless-probe", true), path);
                }
                else
                {
                    Assert.ThrowsExactly<FileNotFoundException>(() => new Executable("extensionless-probe", true));
                }
            });
        }

        [TestMethod]
        [DoNotParallelize]
        public void Constructor_ExplicitExtension_DoesNotAppendExe()
        {
            string path = this.InstallHelper("tools", "probe.custom.exe");
            this.WithEnvironment(Path.GetDirectoryName(path), this.Root, () =>
                Assert.ThrowsExactly<FileNotFoundException>(() => new Executable("probe.custom", true)));
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow("none")]
        [DataRow("null")]
        [DataRow("empty")]
        public void Run_NoArgumentsOverloads_ReturnZeroAndEmptyResults(string overload)
        {
            Executable executable = new Executable(HelperPath, false);
            int exitCode = overload switch
            {
                "none" => executable.Run(),
                "null" => executable.Run(null),
                _ => executable.Run(""),
            };
            Assert.AreEqual(0, exitCode);
            Assert.AreEqual(0, executable.Output.Count);
            Assert.AreEqual(0, executable.Error.Count);
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow(0, -1)]
        [DataRow(7, -1)]
        [DataRow(37, 10000)]
        [DataRow(19, int.MaxValue)]
        public void Run_ExitCodeAndSupportedTimeouts_ReturnChildExitCode(int exitCode, int timeout)
        {
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(exitCode, executable.Run(Arguments("exit", exitCode.ToString()), timeout));
            Assert.AreEqual(0, executable.Output.Count);
            Assert.AreEqual(0, executable.Error.Count);
        }

        [TestMethod]
        [Timeout(30000)]
        public void Run_QuotedArguments_PreservesSpacesEmptyArgumentsQuotesAndBackslashes()
        {
            string[] values = ["plain", "two words", "", "a\"b", "directory with spaces\\", "a\\\"b"];
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(0, executable.Run(Arguments(["arguments", .. values]), 10000));
            Assert.AreEqual(1, executable.Output.Count);
            CollectionAssert.AreEqual(values, JsonSerializer.Deserialize<string[]>(executable.Output[0])!);
            Assert.AreEqual(0, executable.Error.Count);
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow("", null)]
        [DataRow("\n", "")]
        [DataRow("\n\n", "|")]
        [DataRow("\r\n", "")]
        [DataRow("\r", "")]
        [DataRow("first\n\nlast", "first||last")]
        [DataRow("first\r\n\r\nlast\r\n", "first||last")]
        [DataRow("first\r\rlast", "first||last")]
        [DataRow("first\r\nsecond\nthird\rlast", "first|second|third|last")]
        [DataRow(" \n\t\n  last  ", " |\t|  last  ")]
        [DataRow("unterminated", "unterminated")]
        public void Run_LineCapture_PreservesBlankWhitespaceAndUnterminatedLines(string text, string? expected)
        {
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(0, executable.Run(EmitArguments(text, text), 10000));
            string[] lines = expected == null ? [] : expected.Split('|');
            CollectionAssert.AreEqual(lines, executable.Output.ToArray());
            CollectionAssert.AreEqual(lines, executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow("output")]
        [DataRow("error")]
        public void Run_SingleStream_SeparatesOutputAndError(string stream)
        {
            Executable executable = new Executable(HelperPath, false);
            string stdout = stream == "output" ? "out\n" : "";
            string stderr = stream == "error" ? "err\n" : "";
            Assert.AreEqual(0, executable.Run(EmitArguments(stdout, stderr), 10000));
            CollectionAssert.AreEqual(stream == "output" ? new[] { "out" } : [], executable.Output.ToArray());
            CollectionAssert.AreEqual(stream == "error" ? new[] { "err" } : [], executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        public void Run_LongLineAndDefaultEncoding_CapturesRepresentableText()
        {
            string sample = "café Ω 漢字";
            string representable = Console.OutputEncoding.GetString(Console.OutputEncoding.GetBytes(sample));
            // Stay below Windows' command-line length limit while exceeding typical read buffers.
            string line = representable + new string('x', 6000);
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(0, executable.Run(EmitArguments(line, line), 10000));
            CollectionAssert.AreEqual(new[] { line }, executable.Output.ToArray());
            CollectionAssert.AreEqual(new[] { line }, executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow("output")]
        [DataRow("error")]
        [DataRow("both")]
        public void Run_OutputBeyondPipeCapacity_CapturesEveryLineInStreamOrder(string streams)
        {
            const int count = 10000;
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(0, executable.Run(Arguments("volume", count.ToString(), streams), 10000));
            AssertVolume(executable.Output, streams == "error" ? 0 : count, "out");
            AssertVolume(executable.Error, streams == "output" ? 0 : count, "err");
        }

        [TestMethod]
        [Timeout(30000)]
        public void Run_BackToBackRapidExits_ContainsOnlyCompleteLatestResults()
        {
            Executable executable = new Executable(HelperPath, false);
            for (int index = 0; index < 10; index++)
            {
                string line = "run:" + index;
                Assert.AreEqual(0, executable.Run(EmitArguments(line, line), 10000));
                CollectionAssert.AreEqual(new[] { line }, executable.Output.ToArray());
                CollectionAssert.AreEqual(new[] { line }, executable.Error.ToArray());
            }
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow("default")]
        [DataRow("-1")]
        [DataRow("5000")]
        [DataRow("2147483647")]
        public async Task Run_DelayedReaders_WaitsForCompleteCaptureBeforeReturning(string timeout)
        {
            await this.AssertDelayedReaderProbeAsync(timeout, "sync");
        }

        private async Task AssertDelayedReaderProbeAsync(string timeout, string method)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo(HelperPath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            startInfo.ArgumentList.Add("drain-probe");
            startInfo.ArgumentList.Add(Encode(this.Root));
            startInfo.ArgumentList.Add(timeout);
            startInfo.ArgumentList.Add(method);
            using Process probe = Process.Start(startInfo)!;
            try
            {
                Task<string> stdout = probe.StandardOutput.ReadToEndAsync();
                Task<string> stderr = probe.StandardError.ReadToEndAsync();
                Assert.IsTrue(probe.WaitForExit(15000), "Isolated reader probe exceeded its watchdog.");
                string output = await stdout;
                string error = await stderr;
                Assert.AreEqual(0, probe.ExitCode, "Reader probe failed: " + output + error);
                using JsonDocument report = JsonDocument.Parse(output);
                Assert.IsFalse(report.RootElement.GetProperty("returnedBeforeRelease").GetBoolean());
                Assert.AreEqual(method == "cancel", report.RootElement.GetProperty("canceled").GetBoolean());
                if (method == "async-slow-drain")
                {
                    Assert.IsTrue(report.RootElement.GetProperty("nativeExitBeforeDeadline").GetBoolean());
                }
                CollectionAssert.AreEqual(new[] { "out" }, report.RootElement.GetProperty("output").Deserialize<string[]>()!);
                CollectionAssert.AreEqual(new[] { "err" }, report.RootElement.GetProperty("error").Deserialize<string[]>()!);
            }
            finally
            {
                if (!probe.HasExited)
                {
                    probe.Kill(entireProcessTree: true);
                    Assert.IsTrue(probe.WaitForExit(5000));
                }
            }
        }

        [TestMethod]
        [DataRow(-2)]
        [DataRow(int.MinValue)]
        public void Run_InvalidTimeout_ValidatesBeforeAttemptingMissingExecutable(int timeout)
        {
            Executable executable = new Executable(Path.Combine(this.Root, this.executableName), false);
            ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => executable.Run(null, timeout));
            Assert.AreEqual("timeout", exception.ParamName);
            Assert.AreEqual(timeout, exception.ActualValue);
        }

        [TestMethod]
        [Timeout(30000)]
        public void Run_InvalidTimeout_PreservesPreviousResults()
        {
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(0, executable.Run(EmitArguments("old-out", "old-err"), 10000));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => executable.Run(null, -2));
            CollectionAssert.AreEqual(new[] { "old-out" }, executable.Output.ToArray());
            CollectionAssert.AreEqual(new[] { "old-err" }, executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        public void Run_ZeroTimeout_TerminatesBlockedCommand()
        {
            string path = this.InstallHelper("zero-timeout");
            Executable executable = new Executable(path, false);
            Assert.ThrowsExactly<TimeoutException>(() => executable.Run(Arguments("wait", Encode(this.Root)), 0));
            // A terminated native apphost can be moved immediately on Windows too.
            File.Move(path, path + ".finished");
            File.Move(path + ".finished", path);
            Assert.AreEqual(0, executable.Run(Arguments("exit", "0"), 10000));
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow(false)]
        [DataRow(true)]
        public void Run_Timeout_StopsKnownProcessTreeRetainsPartialOutputAndAllowsReuse(bool descendants)
        {
            Executable executable = new Executable(HelperPath, false);
            string mode = descendants ? "tree" : "wait";
            Assert.ThrowsExactly<TimeoutException>(() => executable.Run(Arguments(mode, Encode(this.Root)), 5000));
            Assert.IsTrue(File.Exists(Path.Combine(this.Root, "ready")), "Child must have started before the timeout.");
            CollectionAssert.Contains(executable.Output.ToArray(), "parent-out");
            CollectionAssert.Contains(executable.Error.ToArray(), "parent-err");
            this.AssertStopped("parent");
            if (descendants)
            {
                Assert.IsTrue(File.Exists(Path.Combine(this.Root, "child-ready")));
                this.AssertStopped("child");
            }

            Assert.AreEqual(0, executable.Run(EmitArguments("new-out", "new-err"), 10000));
            CollectionAssert.AreEqual(new[] { "new-out" }, executable.Output.ToArray());
            CollectionAssert.AreEqual(new[] { "new-err" }, executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        public void Run_FailedLaunch_ClearsResultsAndAllowsSuccessfulRetry()
        {
            string path = this.InstallHelper("retry");
            Executable executable = new Executable(path, false);
            Assert.AreEqual(0, executable.Run(EmitArguments("old-out", "old-err"), 10000));
            File.Move(path, path + ".hidden");
            try
            {
                Assert.ThrowsExactly<Win32Exception>(() => executable.Run(null, 10000));
                Assert.AreEqual(0, executable.Output.Count);
                Assert.AreEqual(0, executable.Error.Count);
            }
            finally
            {
                File.Move(path + ".hidden", path);
            }

            Assert.AreEqual(0, executable.Run(EmitArguments("new-out", "new-err"), 10000));
            CollectionAssert.AreEqual(new[] { "new-out" }, executable.Output.ToArray());
            CollectionAssert.AreEqual(new[] { "new-err" }, executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        public void Results_RetainedReadOnlyViews_ReflectSubsequentRuns()
        {
            Executable executable = new Executable(HelperPath, false);
            IList<string> stdout = executable.Output;
            IList<string> stderr = executable.Error;
            Assert.AreEqual(0, executable.Run(EmitArguments("first-out", "first-err"), 10000));
            CollectionAssert.AreEqual(new[] { "first-out" }, stdout.ToArray());
            CollectionAssert.AreEqual(new[] { "first-err" }, stderr.ToArray());
            Assert.AreEqual(0, executable.Run(EmitArguments("second-out", "second-err"), 10000));
            CollectionAssert.AreEqual(new[] { "second-out" }, stdout.ToArray());
            CollectionAssert.AreEqual(new[] { "second-err" }, stderr.ToArray());
            Assert.AreEqual(0, executable.Run(null, 10000));
            Assert.AreEqual(0, stdout.Count);
            Assert.AreEqual(0, stderr.Count);
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow("add")]
        [DataRow("clear")]
        [DataRow("assign")]
        public void Results_MutationAttempts_FailWithoutChangingCapturedLines(string operation)
        {
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(0, executable.Run(EmitArguments("out", "err"), 10000));
            foreach (IList<string> lines in new[] { executable.Output, executable.Error })
            {
                Assert.IsTrue(lines.IsReadOnly);
                Assert.ThrowsExactly<NotSupportedException>(() =>
                {
                    if (operation == "add") lines.Add("changed");
                    else if (operation == "clear") lines.Clear();
                    else lines[0] = "changed";
                });
            }

            CollectionAssert.AreEqual(new[] { "out" }, executable.Output.ToArray());
            CollectionAssert.AreEqual(new[] { "err" }, executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        public async Task Run_SeparateInstances_CaptureConcurrentCommandsIndependently()
        {
            Executable first = new Executable(HelperPath, false);
            Executable second = new Executable(HelperPath, false);
            int[] exitCodes = await Task.WhenAll(
                Task.Run(() => first.Run(Arguments("volume", "1000", "output"), 10000)),
                Task.Run(() => second.Run(Arguments("volume", "1000", "error"), 10000)));
            CollectionAssert.AreEqual(new[] { 0, 0 }, exitCodes);
            AssertVolume(first.Output, 1000, "out");
            Assert.AreEqual(0, first.Error.Count);
            Assert.AreEqual(0, second.Output.Count);
            AssertVolume(second.Error, 1000, "err");
        }

        private void AssertIdentity(Executable executable, string path)
        {
            Assert.AreEqual(0, executable.Run("identity", 10000));
            CollectionAssert.AreEqual(new[] { Path.GetFullPath(path) }, executable.Output.ToArray());
            Assert.AreEqual(0, executable.Error.Count);
        }

        private static void AssertVolume(IList<string> lines, int count, string prefix)
        {
            Assert.AreEqual(count, lines.Count);
            for (int index = 0; index < count; index++)
            {
                Assert.AreEqual($"{prefix}:{index:D5}:" + new string('x', 128), lines[index]);
            }
        }

        private string InstallHelper(string relativeDirectory, string? filename = null)
        {
            string directory = Path.Combine(this.Root, relativeDirectory);
            foreach (string source in Directory.EnumerateFiles(HelperDirectory, "*", SearchOption.AllDirectories))
            {
                string destination = Path.Combine(directory, Path.GetRelativePath(HelperDirectory, source));
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(source, destination);
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(destination, File.GetUnixFileMode(source));
                }
            }

            string target = Path.Combine(directory, filename ?? this.executableName);
            File.Move(Path.Combine(directory, HelperName), target);
            return target;
        }

        private void WithEnvironment(string? pathValue, string currentDirectory, Action action)
        {
            string? oldPath = Environment.GetEnvironmentVariable("PATH");
            string oldDirectory = Directory.GetCurrentDirectory();
            try
            {
                Environment.SetEnvironmentVariable("PATH", pathValue);
                Directory.SetCurrentDirectory(currentDirectory);
                action();
            }
            finally
            {
                Directory.SetCurrentDirectory(oldDirectory);
                Environment.SetEnvironmentVariable("PATH", oldPath);
            }
        }

        private void AssertStopped(string name)
        {
            string marker = Path.Combine(this.Root, name + ".pid");
            Assert.IsTrue(File.Exists(marker), "Expected a PID marker for " + name);
            using Process? process = GetMarkedProcess(marker);
            if (process != null)
            {
                Assert.IsTrue(process.WaitForExit(5000), name + " remained alive after timeout cleanup.");
            }
        }

        private static Process? GetMarkedProcess(string marker)
        {
            string[] identity = File.ReadAllText(marker).Split('|');
            int processId = int.Parse(identity[0]);
            long startTime = long.Parse(identity[1]);
            try
            {
                Process process = Process.GetProcessById(processId);
                if (process.HasExited || process.StartTime.ToUniversalTime().Ticks != startTime)
                {
                    process.Dispose();
                    return null;
                }

                return process;
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        private static string EmitArguments(string stdout, string stderr)
        {
            return Arguments("emit", Encode(stdout), Encode(stderr));
        }

        private static string Encode(string value)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        }

        private static string Arguments(params string[] values)
        {
            return string.Join(' ', values.Select(QuoteArgument));
        }

        private static string QuoteArgument(string value)
        {
            StringBuilder quoted = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }

                quoted.Append('\\', character == '"' ? backslashes * 2 + 1 : backslashes);
                quoted.Append(character);
                backslashes = 0;
            }

            quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }
    }
}
