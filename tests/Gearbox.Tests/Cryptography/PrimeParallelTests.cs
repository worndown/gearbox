using System.Collections.Concurrent;
using System.Numerics;
using Gearbox.Cryptography;

namespace Gearbox.Tests.Cryptography
{
    [TestClass]
    [DoNotParallelize]
    public class PrimeParallelTests
    {
        private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(10);

        [TestMethod]
        public async Task Context_SimultaneousPublishers_PublishesExactlyOneResult()
        {
            using PrimeGenerationContext context = new PrimeGenerationContext(CancellationToken.None);
            using Barrier ready = new Barrier(4);
            BigInteger[] candidates = Enumerable.Range(0, 4).Select(i => (BigInteger.One << 1024) + i).ToArray();
            Task<bool>[] workers = candidates.Select(candidate => Task.Factory.StartNew(() =>
            {
                Assert.IsTrue(ready.SignalAndWait(TestTimeout));
                return context.TryPublish(candidate);
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();

            bool[] published = await Task.WhenAll(workers).WaitAsync(TestTimeout);

            Assert.AreEqual(1, published.Count(value => value));
            Assert.AreEqual(candidates[Array.IndexOf(published, true)], context.GetResult(CancellationToken.None));
            Assert.IsTrue(context.Completed.IsSet);
            Assert.IsTrue(context.CancellationToken.IsCancellationRequested);
        }

        [TestMethod]
        public void Context_FaultAfterWinner_PreservesFirstFailure()
        {
            using PrimeGenerationContext context = new PrimeGenerationContext(CancellationToken.None);
            InvalidOperationException failure = new InvalidOperationException("Worker failed.");
            Assert.IsTrue(context.TryPublish(1009));
            context.Fail(failure);
            context.Fail(new Exception("Later failure."));

            Assert.AreSame(failure, Assert.ThrowsExactly<InvalidOperationException>(() => context.GetResult(CancellationToken.None)));
            Assert.IsFalse(context.TryPublish(1013));
        }

        [TestMethod]
        public void Context_CancellationAfterWinner_PreservesCallerToken()
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            using PrimeGenerationContext context = new PrimeGenerationContext(cancellation.Token);
            Assert.IsTrue(context.TryPublish(1009));
            cancellation.Cancel();

            OperationCanceledException exception = Assert.ThrowsExactly<OperationCanceledException>(() => context.GetResult(cancellation.Token));
            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_Winner_StopsLoserAndWaitsForCleanup(bool asynchronous)
        {
            using CountdownEvent entered = new CountdownEvent(2);
            using ManualResetEventSlim releaseLoser = new ManualResetEventSlim(false);
            RecordingWorkerScheduler scheduler = new RecordingWorkerScheduler();
            int[] draws = new int[2];
            Task<BigInteger> generation = StartGeneration(asynchronous, 13, 2, index => bytes =>
            {
                if (++draws[index] == 1)
                {
                    entered.Signal();
                    Assert.IsTrue(entered.Wait(TestTimeout));
                    if (index == 1)
                    {
                        Assert.IsTrue(releaseLoser.Wait(TestTimeout));
                    }
                    bytes.Fill(0xFF); // 8191 after candidate shaping.
                }
                else
                {
                    bytes.Clear(); // Witness 2 for all 64 rounds.
                }
            }, CancellationToken.None, scheduler);

            try
            {
                Assert.IsTrue(entered.Wait(TestTimeout));
                await scheduler.Workers[0].WaitAsync(TestTimeout);
                Assert.IsFalse(generation.IsCompleted, "Generation must wait for the losing worker.");
            }
            finally
            {
                releaseLoser.Set();
            }

            Assert.AreEqual(new BigInteger(8191), await generation.WaitAsync(TestTimeout));
            Assert.AreEqual(65, draws[0]);
            Assert.AreEqual(1, draws[1]);
            Assert.IsTrue(scheduler.Workers.All(worker => worker.IsCompletedSuccessfully));
            Assert.IsTrue(scheduler.Workers.All(worker => worker.CreationOptions.HasFlag(TaskCreationOptions.LongRunning)));
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_CancelDuringWitnessSampling_StopsAllWorkers(bool asynchronous)
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            using CountdownEvent validating = new CountdownEvent(2);
            using ManualResetEventSlim release = new ManualResetEventSlim(false);
            RecordingWorkerScheduler scheduler = new RecordingWorkerScheduler();
            int[] draws = new int[2];
            Task<BigInteger> generation = StartGeneration(asynchronous, 13, 2, index => bytes =>
            {
                if (++draws[index] == 1)
                {
                    bytes.Fill(0xFF);
                }
                else
                {
                    validating.Signal();
                    Assert.IsTrue(release.Wait(TestTimeout));
                    bytes.Clear();
                }
            }, cancellation.Token, scheduler);

            try
            {
                Assert.IsTrue(validating.Wait(TestTimeout));
                cancellation.Cancel();
                Assert.IsFalse(generation.IsCompleted);
            }
            finally
            {
                release.Set();
            }

            OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => generation.WaitAsync(TestTimeout));
            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.IsTrue(generation.IsCanceled);
            CollectionAssert.AreEqual(new[] { 2, 2 }, draws);
            Assert.IsTrue(scheduler.Workers.All(worker => worker.IsCompletedSuccessfully));
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_WorkerFault_StopsPeersAndPreservesException(bool asynchronous)
        {
            using CountdownEvent entered = new CountdownEvent(2);
            using ManualResetEventSlim releasePeer = new ManualResetEventSlim(false);
            RecordingWorkerScheduler scheduler = new RecordingWorkerScheduler();
            InvalidOperationException failure = new InvalidOperationException("Random source failed.");
            int[] draws = new int[2];
            Task<BigInteger> generation = StartGeneration(asynchronous, 13, 2, index => bytes =>
            {
                draws[index]++;
                entered.Signal();
                Assert.IsTrue(entered.Wait(TestTimeout));
                if (index == 0)
                {
                    throw failure;
                }
                Assert.IsTrue(releasePeer.Wait(TestTimeout));
                bytes.Fill(0xFF);
            }, CancellationToken.None, scheduler);

            try
            {
                Assert.IsTrue(entered.Wait(TestTimeout));
                await scheduler.Workers[0].WaitAsync(TestTimeout);
                Assert.IsFalse(generation.IsCompleted);
            }
            finally
            {
                releasePeer.Set();
            }

            Assert.AreSame(failure, await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => generation.WaitAsync(TestTimeout)));
            Assert.IsTrue(generation.IsFaulted);
            CollectionAssert.AreEqual(new[] { 1, 1 }, draws);
            Assert.IsTrue(scheduler.Workers.All(worker => worker.IsCompletedSuccessfully));
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_PartialStartupFailure_WaitsForStartedWorker(bool asynchronous)
        {
            using ManualResetEventSlim entered = new ManualResetEventSlim(false);
            using ManualResetEventSlim release = new ManualResetEventSlim(false);
            InvalidOperationException failure = new InvalidOperationException("Cannot start worker.");
            RecordingWorkerScheduler scheduler = new RecordingWorkerScheduler(number =>
            {
                if (number == 2)
                {
                    Assert.IsTrue(entered.Wait(TestTimeout));
                    throw failure;
                }
            });
            Task<BigInteger> generation = StartGeneration(asynchronous, 13, 4, _ => bytes =>
            {
                entered.Set();
                Assert.IsTrue(release.Wait(TestTimeout));
                bytes.Fill(0xFF);
            }, CancellationToken.None, scheduler);

            try
            {
                Assert.IsTrue(entered.Wait(TestTimeout));
                Assert.IsFalse(generation.IsCompleted);
            }
            finally
            {
                release.Set();
            }

            TaskSchedulerException exception = await Assert.ThrowsExactlyAsync<TaskSchedulerException>(() => generation.WaitAsync(TestTimeout));
            Assert.AreSame(failure, exception.InnerException);
            Assert.HasCount(1, scheduler.Workers);
            Assert.IsTrue(scheduler.Workers[0].IsCompletedSuccessfully);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_UnrelatedCancellationException_IsWorkerFault(bool asynchronous)
        {
            OperationCanceledException failure = new OperationCanceledException(new CancellationToken(true));
            Task<BigInteger> generation = StartGeneration(asynchronous, 13, 2, _ => throw failure, CancellationToken.None);

            Assert.AreSame(failure, await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => generation.WaitAsync(TestTimeout)));
            Assert.IsTrue(generation.IsFaulted);
        }

        [TestMethod]
        public async Task Generate_IndependentCalls_UseIndependentDedicatedWorkers()
        {
            using Barrier entered = new Barrier(4);
            bool[] threadPoolWorkers = new bool[4];
            int[] draws = new int[4];
            Func<int, Prime.RandomByteFiller> Source(int operation) => index => bytes =>
            {
                int worker = operation * 2 + index;
                threadPoolWorkers[worker] = Thread.CurrentThread.IsThreadPoolThread;
                if (++draws[worker] == 1)
                {
                    Assert.IsTrue(entered.SignalAndWait(TestTimeout));
                    bytes[0] = 0x03;
                    bytes[1] = operation == 0 ? (byte)0xF1 : (byte)0xF5; // 1009 and 1013.
                }
                else
                {
                    bytes.Clear();
                }
            };
            Task<BigInteger> first = Prime.GenerateAsync(10, 2, Source(0), CancellationToken.None);
            Task<BigInteger> second = Prime.GenerateAsync(10, 2, Source(1), CancellationToken.None);

            BigInteger[] results = await Task.WhenAll(first, second).WaitAsync(TestTimeout);

            CollectionAssert.AreEqual(new[] { new BigInteger(1009), new BigInteger(1013) }, results);
            Assert.IsFalse(threadPoolWorkers.Any(value => value));
            Assert.IsTrue(draws.All(value => value >= 1 && value <= 65));
        }

        [TestMethod]
        public async Task Generate_PreCanceledToken_DoesNotStartWorkers()
        {
            CancellationToken token = new CancellationToken(true);
            Func<int, Prime.RandomByteFiller> source = _ => throw new AssertFailedException("No worker should start.");
            OperationCanceledException sync = Assert.ThrowsExactly<OperationCanceledException>(() => Prime.Generate(int.MaxValue, 2, source, token));
            Task<BigInteger> asynchronous = Prime.GenerateAsync(int.MaxValue, 2, source, token);
            OperationCanceledException async = await Assert.ThrowsAsync<OperationCanceledException>(() => asynchronous);

            Assert.AreEqual(token, sync.CancellationToken);
            Assert.AreEqual(token, async.CancellationToken);
            Assert.IsTrue(asynchronous.IsCanceled);
        }

        [TestMethod]
        public void Generate_InvalidWorkerSettings_ThrowsSynchronously()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Prime.GenerateAsync(13, 0, _ => FillZero, CancellationToken.None));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Prime.Generate(1, 2, _ => FillZero, CancellationToken.None));
            Assert.ThrowsExactly<ArgumentNullException>(() => Prime.GenerateAsync(13, 2, null!, CancellationToken.None));
        }

        [TestMethod]
        public void Generate_WorkerThreshold_KeepsSmallRequestsSerial()
        {
            Assert.AreEqual(1, Prime.GetGenerationWorkerCount(511));
            Assert.AreEqual(ProcessorTopology.WorkerCount, Prime.GetGenerationWorkerCount(512));
        }

        [TestMethod]
        public async Task GenerateAsync_RealRandomSource_UsesLargePrimePath()
        {
            BigInteger result = await Prime.GenerateAsync(512).WaitAsync(TestTimeout);

            Assert.AreEqual(512L, result.GetBitLength());
            Assert.IsTrue(Prime.IsProbablePrime(result));
        }

        private static Task<BigInteger> StartGeneration(bool asynchronous, int bitLength, int workerCount,
            Func<int, Prime.RandomByteFiller> source, CancellationToken token, TaskScheduler? scheduler = null) =>
            asynchronous ? Prime.GenerateAsync(bitLength, workerCount, source, token, scheduler)
                : Task.Run(() => Prime.Generate(bitLength, workerCount, source, token, scheduler), token);

        private static void FillZero(Span<byte> bytes) => bytes.Clear();

        private sealed class RecordingWorkerScheduler(Action<int>? beforeQueue = null) : TaskScheduler
        {
            private readonly ConcurrentQueue<Task> workers = new ConcurrentQueue<Task>();
            private int queueCount;
            internal Task[] Workers => workers.ToArray();

            protected override void QueueTask(Task task)
            {
                beforeQueue?.Invoke(Interlocked.Increment(ref queueCount));
                workers.Enqueue(task);
                new Thread(() => TryExecuteTask(task)) { IsBackground = true }.Start();
            }

            protected override bool TryExecuteTaskInline(Task task, bool taskWasPreviouslyQueued) => false;
            protected override IEnumerable<Task> GetScheduledTasks() => workers.ToArray();
        }
    }
}
