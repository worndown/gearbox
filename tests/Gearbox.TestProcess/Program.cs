using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Gearbox.TestProcess
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            // A broken runner must not leave an indefinitely blocked test child behind.
            using Timer watchdog = new Timer(_ => Environment.Exit(124), null, 20000, Timeout.Infinite);
            if (args.Length == 0)
            {
                return 0;
            }

            switch (args[0])
            {
                case "exit":
                    return int.Parse(args[1]);
                case "arguments":
                    Console.WriteLine(JsonSerializer.Serialize(args.Skip(1).ToArray()));
                    return 0;
                case "identity":
                    Console.WriteLine(Environment.ProcessPath);
                    return 0;
                case "emit":
                    Console.Out.Write(Decode(args[1]));
                    Console.Error.Write(Decode(args[2]));
                    return 0;
                case "volume":
                    WriteVolume(int.Parse(args[1]), args[2]);
                    return 0;
                case "wait":
                case "tree":
                case "child":
                    Wait(Decode(args[1]), args[0]);
                    return 0;
                case "drain-child":
                    WriteProcessMarker(Decode(args[1]), "drain-child");
                    Console.Out.WriteLine("out");
                    Console.Error.WriteLine("err");
                    Console.Out.Flush();
                    Console.Error.Flush();
                    File.WriteAllText(Path.Combine(Decode(args[1]), "drain-ready"), "ready");
                    return 0;
                case "drain-probe":
                    return CheckDelayedReaders(Decode(args[1]), args[2]);
                default:
                    throw new ArgumentException("Unknown test process mode: " + args[0]);
            }
        }

        private static string Decode(string value)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(value));
        }

        private static string Encode(string value)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        }

        private static void WriteVolume(int count, string streams)
        {
            void Write(TextWriter writer, string prefix)
            {
                for (int index = 0; index < count; index++)
                {
                    writer.WriteLine($"{prefix}:{index:D5}:" + new string('x', 128));
                }
            }

            // Independent writers exercise pressure on both redirected pipes together.
            Thread stdout = new Thread(() => { if (streams != "error") Write(Console.Out, "out"); });
            Thread stderr = new Thread(() => { if (streams != "output") Write(Console.Error, "err"); });
            stdout.Start();
            stderr.Start();
            stdout.Join();
            stderr.Join();
        }

        private static void WriteProcessMarker(string directory, string name)
        {
            using Process process = Process.GetCurrentProcess();
            File.WriteAllText(Path.Combine(directory, name + ".pid"),
                $"{process.Id}|{process.StartTime.ToUniversalTime().Ticks}");
        }

        private static void Wait(string directory, string mode)
        {
            WriteProcessMarker(directory, mode == "child" ? "child" : "parent");
            using Process? child = mode == "tree" ? StartChild(directory) : null;
            if (child != null)
            {
                WaitForFile(Path.Combine(directory, "child-ready"));
            }

            Console.Out.WriteLine(mode == "child" ? "child-out" : "parent-out");
            Console.Error.WriteLine(mode == "child" ? "child-err" : "parent-err");
            Console.Out.Flush();
            Console.Error.Flush();
            File.WriteAllText(Path.Combine(directory, mode == "child" ? "child-ready" : "ready"), "ready");
            Thread.Sleep(Timeout.Infinite);
        }

        private static Process StartChild(string directory)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo(Environment.ProcessPath!)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("child");
            startInfo.ArgumentList.Add(Encode(directory));
            return Process.Start(startInfo)!;
        }

        private static void WaitForFile(string path)
        {
            Stopwatch watch = Stopwatch.StartNew();
            while (!File.Exists(path))
            {
                if (watch.ElapsedMilliseconds > 5000)
                {
                    throw new TimeoutException("Test child did not signal readiness: " + path);
                }

                Thread.Sleep(10);
            }
        }

        private static int CheckDelayedReaders(string directory, string timeout)
        {
            ThreadPool.GetMinThreads(out int oldMinWorkers, out int oldMinIo);
            ThreadPool.GetMaxThreads(out int oldMaxWorkers, out int oldMaxIo);
            using ManualResetEventSlim releaseReaders = new ManualResetEventSlim(false);
            using ManualResetEventSlim runFinished = new ManualResetEventSlim(false);
            using CountdownEvent started = new CountdownEvent(2);
            using CountdownEvent finished = new CountdownEvent(2);
            Exception? watcherFailure = null;
            int readersReleased = 0;
            Thread? watcher = null;
            try
            {
                if (!ThreadPool.SetMinThreads(1, oldMinIo) || !ThreadPool.SetMaxThreads(2, oldMaxIo))
                {
                    throw new InvalidOperationException("Cannot gate reader workers in the isolated probe.");
                }

                for (int index = 0; index < 2; index++)
                {
                    ThreadPool.QueueUserWorkItem(_ =>
                    {
                        started.Signal();
                        releaseReaders.Wait();
                        finished.Signal();
                    });
                }

                if (!started.Wait(5000))
                {
                    throw new TimeoutException("Reader gates did not start.");
                }

                watcher = new Thread(() =>
                {
                    try
                    {
                        WaitForFile(Path.Combine(directory, "drain-ready"));
                        int childId = int.Parse(File.ReadAllText(Path.Combine(directory, "drain-child.pid")).Split('|')[0]);
                        try
                        {
                            using Process child = Process.GetProcessById(childId);
                            if (!child.WaitForExit(5000))
                            {
                                throw new TimeoutException("Drain child did not exit.");
                            }
                        }
                        catch (ArgumentException)
                        {
                            // The child may already have exited and been reaped.
                        }

                        // A correct Run is still waiting for readers after native process exit.
                        runFinished.Wait(500);
                    }
                    catch (Exception exception)
                    {
                        watcherFailure = exception;
                    }
                    finally
                    {
                        Volatile.Write(ref readersReleased, 1);
                        releaseReaders.Set();
                    }
                });
                watcher.Start();

                Executable executable = new Executable(Environment.ProcessPath!, false);
                string arguments = "drain-child " + Encode(directory);
                int exitCode = timeout == "default"
                    ? executable.Run(arguments)
                    : executable.Run(arguments, int.Parse(timeout));
                bool returnedBeforeRelease = Volatile.Read(ref readersReleased) == 0;
                string[] output = executable.Output.ToArray();
                string[] error = executable.Error.ToArray();
                runFinished.Set();
                watcher.Join();
                if (watcherFailure != null)
                {
                    throw new InvalidOperationException("Drain watcher failed.", watcherFailure);
                }

                Console.WriteLine(JsonSerializer.Serialize(new { exitCode, returnedBeforeRelease, output, error }));
                return exitCode == 0 && !returnedBeforeRelease
                    && output.SequenceEqual(["out"]) && error.SequenceEqual(["err"]) ? 0 : 1;
            }
            finally
            {
                runFinished.Set();
                releaseReaders.Set();
                ThreadPool.SetMaxThreads(oldMaxWorkers, oldMaxIo);
                ThreadPool.SetMinThreads(oldMinWorkers, oldMinIo);
                watcher?.Join();
                if (started.CurrentCount == 0)
                {
                    finished.Wait(5000);
                }
            }
        }
    }
}
