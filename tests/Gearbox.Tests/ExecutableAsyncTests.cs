using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;

namespace Gearbox.Tests
{
    public partial class ExecutableTests
    {
        [TestMethod]
        [Timeout(30000)]
        [DataRow("default")]
        [DataRow("null")]
        [DataRow("empty")]
        public async Task RunAsync_NoArguments_ReturnsZeroAndEmptyResults(string arguments)
        {
            Executable executable = new Executable(HelperPath, false);
            int exitCode = arguments switch
            {
                "default" => await executable.RunAsync(),
                "null" => await executable.RunAsync(null),
                _ => await executable.RunAsync(""),
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
        public async Task RunAsync_SupportedTimeouts_ReturnsChildExitCode(int exitCode, int timeout)
        {
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(exitCode, await executable.RunAsync(Arguments("exit", exitCode.ToString()), timeout));
            Assert.AreEqual(0, executable.Output.Count);
            Assert.AreEqual(0, executable.Error.Count);
        }

        [TestMethod]
        [Timeout(30000)]
        public async Task RunAsync_QuotedArguments_PreservesArgumentValues()
        {
            string[] values = ["plain", "two words", "", "a\"b", "directory with spaces\\"];
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(0, await executable.RunAsync(Arguments(["arguments", .. values])));
            Assert.AreEqual(1, executable.Output.Count);
            CollectionAssert.AreEqual(values, JsonSerializer.Deserialize<string[]>(executable.Output[0])!);
            Assert.AreEqual(0, executable.Error.Count);
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow("", null)]
        [DataRow("\n", "")]
        [DataRow("first\r\n\r\n \n\t\rlast", "first|| |\t|last")]
        [DataRow("unterminated", "unterminated")]
        public async Task RunAsync_LineCapture_PreservesBothStreams(string text, string? expected)
        {
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(0, await executable.RunAsync(EmitArguments(text, text)));
            string[] lines = expected == null ? [] : expected.Split('|');
            CollectionAssert.AreEqual(lines, executable.Output.ToArray());
            CollectionAssert.AreEqual(lines, executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow("output")]
        [DataRow("error")]
        [DataRow("both")]
        public async Task RunAsync_OutputBeyondPipeCapacity_CapturesEveryLine(string streams)
        {
            const int count = 10000;
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(0, await executable.RunAsync(Arguments("volume", count.ToString(), streams), 10000));
            AssertVolume(executable.Output, streams == "error" ? 0 : count, "out");
            AssertVolume(executable.Error, streams == "output" ? 0 : count, "err");
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow("default")]
        [DataRow("-1")]
        [DataRow("5000")]
        [DataRow("2147483647")]
        public async Task RunAsync_DelayedReaders_WaitsForCompleteCaptureBeforeReturning(string timeout)
        {
            await this.AssertDelayedReaderProbeAsync(timeout, "async");
        }

        [TestMethod]
        [Timeout(30000)]
        public async Task RunAsync_CanceledDuringOutputDraining_FinishesCaptureBeforeTaskCancellation()
        {
            await this.AssertDelayedReaderProbeAsync("default", "cancel");
        }

        [TestMethod]
        [Timeout(30000)]
        public async Task RunAsync_ProcessExitTimeout_DoesNotTimeOutDelayedOutputDraining()
        {
            await this.AssertDelayedReaderProbeAsync("5000", "async-slow-drain");
        }

        [TestMethod]
        [DataRow(-2)]
        [DataRow(int.MinValue)]
        public void RunAsync_InvalidTimeout_ValidatesSynchronouslyBeforeLaunch(int timeout)
        {
            Executable executable = new Executable(Path.Combine(this.Root, this.executableName), false);
            ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            {
                _ = executable.RunAsync(timeout: timeout);
            });
            Assert.AreEqual("timeout", exception.ParamName);
            Assert.AreEqual(timeout, exception.ActualValue);
        }

        [TestMethod]
        [Timeout(30000)]
        public async Task RunAsync_InvalidTimeout_PreservesPreviousResults()
        {
            Executable executable = new Executable(HelperPath, false);
            Assert.AreEqual(0, await executable.RunAsync(EmitArguments("old-out", "old-err")));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => { _ = executable.RunAsync(timeout: -2); });
            CollectionAssert.AreEqual(new[] { "old-out" }, executable.Output.ToArray());
            CollectionAssert.AreEqual(new[] { "old-err" }, executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        public async Task RunAsync_PreCanceledToken_PreventsLaunchPreservesResultsAndAllowsReuse()
        {
            string path = this.InstallHelper("pre-canceled");
            Executable executable = new Executable(path, false);
            Assert.AreEqual(0, await executable.RunAsync(EmitArguments("old-out", "old-err")));
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            File.Move(path, path + ".hidden");
            try
            {
                // A launch attempt would fail with Win32Exception because the apphost is absent.
                Task<int> run = executable.RunAsync(cancellationToken: cancellation.Token);
                OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => run);
                Assert.AreEqual(cancellation.Token, exception.CancellationToken);
                Assert.IsTrue(run.IsCanceled);
                CollectionAssert.AreEqual(new[] { "old-out" }, executable.Output.ToArray());
                CollectionAssert.AreEqual(new[] { "old-err" }, executable.Error.ToArray());
            }
            finally
            {
                File.Move(path + ".hidden", path);
            }

            Assert.AreEqual(0, await executable.RunAsync());
            Assert.AreEqual(0, executable.Output.Count);
            Assert.AreEqual(0, executable.Error.Count);
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow(false)]
        [DataRow(true)]
        public async Task RunAsync_Cancellation_ReturnsPendingTaskThenStopsTreeAndRetainsOutput(bool descendants)
        {
            Executable executable = new Executable(HelperPath, false);
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            Task<int> run = executable.RunAsync(Arguments(descendants ? "tree" : "wait", Encode(this.Root)),
                timeout: descendants ? 10000 : System.Threading.Timeout.Infinite,
                cancellationToken: cancellation.Token);
            try
            {
                await this.WaitForReadyAsync();
                Assert.IsFalse(run.IsCompleted, "RunAsync must return control while the command is still running.");
                cancellation.Cancel();
                OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => run);
                Assert.AreEqual(cancellation.Token, exception.CancellationToken);
                Assert.IsTrue(run.IsCanceled);
                CollectionAssert.Contains(executable.Output.ToArray(), "parent-out");
                CollectionAssert.Contains(executable.Error.ToArray(), "parent-err");
                this.AssertStopped("parent");
                if (descendants)
                {
                    this.AssertStopped("child");
                }
            }
            finally
            {
                cancellation.Cancel();
                try { await run; }
                catch (OperationCanceledException) { }
            }

            Assert.AreEqual(0, await executable.RunAsync(EmitArguments("new-out", "new-err")));
            CollectionAssert.AreEqual(new[] { "new-out" }, executable.Output.ToArray());
            CollectionAssert.AreEqual(new[] { "new-err" }, executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        [DataRow(false)]
        [DataRow(true)]
        public async Task RunAsync_Timeout_StopsTreeRetainsPartialOutputAndAllowsReuse(bool descendants)
        {
            Executable executable = new Executable(HelperPath, false);
            Task<int> run = executable.RunAsync(Arguments(descendants ? "tree" : "wait", Encode(this.Root)), 5000);
            await Assert.ThrowsExactlyAsync<TimeoutException>(() => run);
            Assert.IsTrue(run.IsFaulted);
            Assert.IsTrue(File.Exists(Path.Combine(this.Root, "ready")), "The command must have started before timing out.");
            CollectionAssert.Contains(executable.Output.ToArray(), "parent-out");
            CollectionAssert.Contains(executable.Error.ToArray(), "parent-err");
            this.AssertStopped("parent");
            if (descendants)
            {
                this.AssertStopped("child");
            }

            Assert.AreEqual(0, await executable.RunAsync());
            Assert.AreEqual(0, executable.Output.Count);
            Assert.AreEqual(0, executable.Error.Count);
        }

        [TestMethod]
        [Timeout(30000)]
        public async Task RunAsync_ZeroTimeout_TerminatesBlockedCommand()
        {
            string path = this.InstallHelper("async-zero-timeout");
            Executable executable = new Executable(path, false);
            await Assert.ThrowsExactlyAsync<TimeoutException>(() => executable.RunAsync(Arguments("wait", Encode(this.Root)), 0));
            File.Move(path, path + ".finished");
            File.Move(path + ".finished", path);
            Assert.AreEqual(0, await executable.RunAsync());
        }

        [TestMethod]
        [Timeout(30000)]
        public async Task RunAsync_LaunchFailure_FaultsTaskClearsResultsAndAllowsRetry()
        {
            string path = this.InstallHelper("async-retry");
            Executable executable = new Executable(path, false);
            Assert.AreEqual(0, await executable.RunAsync(EmitArguments("old-out", "old-err")));
            File.Move(path, path + ".hidden");
            try
            {
                Task<int> run = executable.RunAsync();
                await Assert.ThrowsExactlyAsync<Win32Exception>(() => run);
                Assert.IsTrue(run.IsFaulted);
                Assert.AreEqual(0, executable.Output.Count);
                Assert.AreEqual(0, executable.Error.Count);
            }
            finally
            {
                File.Move(path + ".hidden", path);
            }

            Assert.AreEqual(0, await executable.RunAsync(EmitArguments("new-out", "new-err")));
            CollectionAssert.AreEqual(new[] { "new-out" }, executable.Output.ToArray());
            CollectionAssert.AreEqual(new[] { "new-err" }, executable.Error.ToArray());
        }

        [TestMethod]
        [Timeout(30000)]
        public async Task RunAsync_LiveViews_ReflectSyncAndAsyncRuns()
        {
            Executable executable = new Executable(HelperPath, false);
            IList<string> output = executable.Output;
            IList<string> error = executable.Error;
            Assert.AreEqual(0, executable.Run(EmitArguments("sync-out", "sync-err"), 10000));
            Assert.AreEqual(0, await executable.RunAsync(EmitArguments("async-out", "async-err")));
            CollectionAssert.AreEqual(new[] { "async-out" }, output.ToArray());
            CollectionAssert.AreEqual(new[] { "async-err" }, error.ToArray());
            Assert.IsTrue(output.IsReadOnly);
            Assert.IsTrue(error.IsReadOnly);
            Assert.AreEqual(0, executable.Run(null, 10000));
            Assert.AreEqual(0, output.Count);
            Assert.AreEqual(0, error.Count);
        }

        [TestMethod]
        [Timeout(30000)]
        public async Task RunAsync_SeparateInstances_CaptureConcurrentCommandsIndependently()
        {
            Executable first = new Executable(HelperPath, false);
            Executable second = new Executable(HelperPath, false);
            int[] exitCodes = await Task.WhenAll(
                first.RunAsync(Arguments("volume", "1000", "output")),
                second.RunAsync(Arguments("volume", "1000", "error")));
            CollectionAssert.AreEqual(new[] { 0, 0 }, exitCodes);
            AssertVolume(first.Output, 1000, "out");
            Assert.AreEqual(0, first.Error.Count);
            Assert.AreEqual(0, second.Output.Count);
            AssertVolume(second.Error, 1000, "err");
        }

        private async Task WaitForReadyAsync()
        {
            Stopwatch watch = Stopwatch.StartNew();
            while (!File.Exists(Path.Combine(this.Root, "ready")))
            {
                Assert.IsTrue(watch.ElapsedMilliseconds < 10000, "The command did not signal readiness.");
                await Task.Delay(10);
            }
        }
    }
}
