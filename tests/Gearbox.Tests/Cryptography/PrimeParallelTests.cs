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
            using PrimeGenerationContext context = ReadyContext(4);
            using Barrier ready = new Barrier(4);
            BigInteger[] candidates = Enumerable.Range(0, 4).Select(i => (BigInteger.One << 1024) + i).ToArray();
            Task<bool>[] workers = candidates.Select((candidate, index) => Task.Factory.StartNew(() =>
            {
                Assert.IsTrue(context.Acquire(index, out PrimeAdmissionTicket ticket, false));
                Assert.IsTrue(ready.SignalAndWait(TestTimeout));
                context.CompleteSearch(ticket, PreparationOutcome.KnownPrime, candidate);
                return context.Snapshot().Result == candidate;
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
            using PrimeGenerationContext context = ReadyContext(2);
            InvalidOperationException failure = new InvalidOperationException("Worker failed.");
            PublishKnown(context, 1009);
            context.Fail(failure);
            context.Fail(new Exception("Later failure."));

            Assert.AreSame(failure, Assert.ThrowsExactly<InvalidOperationException>(() => context.GetResult(CancellationToken.None)));
            Assert.IsFalse(context.Acquire(0, out _, false));
        }

        [TestMethod]
        public void Context_CancellationAfterWinner_PreservesCallerToken()
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            using PrimeGenerationContext context = ReadyContext(2, cancellation.Token);
            PublishKnown(context, 1009);
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
            using ManualResetEventSlim promoted = new(false);
            TestObserver observer = new() { OnPhase = (phase, _, _) =>
            {
                if (phase == PrimeGenerationPhase.DrainingSearch) promoted.Set();
            }};
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
            }, CancellationToken.None, scheduler, observer);

            try
            {
                Assert.IsTrue(entered.Wait(TestTimeout));
                Assert.IsTrue(promoted.Wait(TestTimeout));
                Assert.IsFalse(generation.IsCompleted, "Validation must wait for admitted search jobs to drain.");
                Assert.IsFalse(scheduler.Workers[0].IsCompleted);
            }
            finally
            {
                releaseLoser.Set();
            }

            Assert.AreEqual(new BigInteger(8191), await generation.WaitAsync(TestTimeout));
            Assert.AreEqual(66, draws.Sum()); // Two candidates, 64 collectively executed rounds.
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
            TestObserver observer = new() { OnReady = _ =>
            {
                entered.Set();
                Assert.IsTrue(release.Wait(TestTimeout));
            }};
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
                Assert.Fail("Startup must not admit candidate work.");
            }, CancellationToken.None, scheduler, observer);

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
        public void Generate_256BitControl_PreservesSerialRouteAndDeterministicDraws()
        {
            BigInteger knownPrime = (BigInteger.One << 256) - 189;
            byte[] candidate = knownPrime.ToByteArray(isUnsigned: true, isBigEndian: true);
            int[] draws = new int[2];
            Prime.RandomByteFiller Source(int mode) => bytes =>
            {
                Assert.IsTrue(bytes.IndexOfAnyExcept((byte)0) < 0, "Worker buffers must be cleared between jobs.");
                if (++draws[mode] == 1) candidate.CopyTo(bytes); else bytes.Clear();
            };
            Assert.AreEqual(1, Prime.GetGenerationWorkerCount(256));
            Assert.AreEqual(knownPrime, Prime.Generate(256, Source(0), default));
            Assert.AreEqual(knownPrime, Prime.Generate(256, 1, _ => Source(1), default));
            CollectionAssert.AreEqual(new[] { 65, 65 }, draws);
        }

        [TestMethod]
        public async Task GenerateAsync_RealRandomSource_UsesLargePrimePath()
        {
            BigInteger result = await Prime.GenerateAsync(512).WaitAsync(TestTimeout);

            Assert.AreEqual(512L, result.GetBitLength());
            Assert.IsTrue(Prime.IsProbablePrime(result));
        }

        private static Task<BigInteger> StartGeneration(bool asynchronous, int bitLength, int workerCount,
            Func<int, Prime.RandomByteFiller> source, CancellationToken token, TaskScheduler? scheduler = null,
            IPrimeGenerationObserver? observer = null) =>
            asynchronous ? Prime.GenerateAsync(bitLength, workerCount, source, token, scheduler, observer)
                : Task.Run(() => Prime.Generate(bitLength, workerCount, source, token, scheduler, observer), token);

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_ObserverSeparatesDraws_ResamplingClaimsOnly64RoundsAndReusesWorkers(bool asynchronous)
        {
            RecordingWorkerScheduler scheduler = new();
            int[] factories = new int[3];
            int[] jobKind = new int[3];
            int[] searchDraws = new int[3];
            int[] roundDraws = new int[3];
            int[] resamplingStep = new int[3];
            ConcurrentBag<int> rounds = new();
            ConcurrentBag<(long Sequence, PrimeGenerationPhase Phase)> phases = new();
            TestObserver observer = new()
            {
                OnSearch = (worker, _, _) => jobKind[worker] = 0,
                OnRound = (worker, _, round, _) =>
                {
                    jobKind[worker] = 1;
                    resamplingStep[worker] = 0;
                    rounds.Add(round);
                },
                OnPhase = (phase, _, sequence) => phases.Add((sequence, phase))
            };
            BigInteger prime = await StartGeneration(asynchronous, 13, 3, worker =>
            {
                factories[worker]++;
                return bytes =>
                {
                    if (jobKind[worker] == 0)
                    {
                        // Every initialized worker draws fresh composites before supplying a prime.
                        if (++searchDraws[worker] <= 3) bytes.Clear(); // 4097 = 17 * 241.
                        else bytes.Fill(0xFF); // 8191.
                    }
                    else
                    {
                        Assert.AreEqual(2, bytes.Length);
                        roundDraws[worker]++;
                        if (resamplingStep[worker]++ == 0) bytes.Fill(0xFF); // 8191 >= n - 3: reject.
                        else bytes.Clear();
                    }
                };
            }, default, scheduler, observer).WaitAsync(TestTimeout);
            Assert.AreEqual(new BigInteger(8191), prime);
            CollectionAssert.AreEqual(new[] { 1, 1, 1 }, factories);
            CollectionAssert.AreEquivalent(Enumerable.Range(0, 64).ToArray(), rounds.ToArray());
            Assert.AreEqual(128, roundDraws.Sum());
            Assert.AreEqual(3, scheduler.Workers.Length);
            CollectionAssert.AreEqual(new[] { PrimeGenerationPhase.Searching, PrimeGenerationPhase.DrainingSearch,
                PrimeGenerationPhase.Validating, PrimeGenerationPhase.Stopping },
                phases.OrderBy(item => item.Sequence).Select(item => item.Phase).ToArray());
            Assert.IsTrue(scheduler.Workers.All(worker => worker.IsCompletedSuccessfully));
        }

        [TestMethod]
        [DataRow(false, 0, 2)]
        [DataRow(true, 0, 2)]
        [DataRow(false, 255, 3)]
        [DataRow(true, 255, 3)]
        public async Task Generate_ForcedParallelKnownPrime_DoesNotInventRandomRounds(bool asynchronous, int raw, int expected)
        {
            int rounds = 0;
            BigInteger result = await StartGeneration(asynchronous, 2, 2, _ => bytes => bytes.Fill((byte)raw), default,
                observer: new TestObserver { OnRound = (_, _, _, _) => Interlocked.Increment(ref rounds) }).WaitAsync(TestTimeout);
            Assert.AreEqual(new BigInteger(expected), result);
            Assert.AreEqual(0, rounds);
        }

        [TestMethod]
        [DataRow(false, 0)]
        [DataRow(true, 0)]
        [DataRow(false, 1)]
        [DataRow(true, 1)]
        [DataRow(false, 2)]
        [DataRow(true, 2)]
        [DataRow(false, 3)]
        [DataRow(true, 3)]
        [DataRow(false, 4)]
        [DataRow(true, 4)]
        public async Task Generate_ObserverFaultsInReadinessSearchValidationRetirementAndPublication_Propagate(bool asynchronous, int point)
        {
            InvalidOperationException failure = new("Observer failed.");
            TestObserver observer = new()
            {
                OnReady = _ => { if (point == 0) throw failure; },
                OnSearch = (_, _, _) => { if (point == 1) throw failure; },
                OnRound = (_, _, _, _) => { if (point == 2) throw failure; },
                OnRetire = _ => { if (point == 3) throw failure; },
                OnPhase = (phase, _, _) => { if (point == 4 && phase == PrimeGenerationPhase.Stopping) throw failure; }
            };
            int[] kind = new int[2];
            if (point != 1) observer.OnSearch = (worker, _, _) => kind[worker] = 0;
            if (point != 2) observer.OnRound = (worker, _, _, _) => kind[worker] = 1;
            Task<BigInteger> task = StartGeneration(asynchronous, 13, 2, worker => bytes =>
            {
                if (kind[worker] == 0) bytes.Fill(0xFF); else bytes.Clear();
            }, default, observer: observer);
            Assert.AreSame(failure, await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => task.WaitAsync(TestTimeout)));
            Assert.IsTrue(task.IsFaulted);
        }

        [TestMethod]
        [DataRow(false, false)]
        [DataRow(true, false)]
        [DataRow(false, true)]
        [DataRow(true, true)]
        public async Task Generate_UnexpectedWitnessFaultIncludingUnrelatedCancellation_RemainsFaulted(bool asynchronous, bool unrelatedCancellation)
        {
            Exception failure = unrelatedCancellation ? new OperationCanceledException(new CancellationToken(true))
                : new InvalidOperationException("Witness failed.");
            int[] kind = new int[2];
            TestObserver observer = new() { OnRound = (worker, _, _, _) => kind[worker] = 1 };
            Task<BigInteger> task = StartGeneration(asynchronous, 13, 2, worker => bytes =>
            {
                if (kind[worker] == 1) throw failure;
                bytes.Fill(0xFF);
            }, default, observer: observer);
            Exception thrown = unrelatedCancellation
                ? await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => task.WaitAsync(TestTimeout))
                : await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => task.WaitAsync(TestTimeout));
            Assert.AreSame(failure, thrown);
            Assert.IsTrue(task.IsFaulted);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_CancellationAfterProvisionalResult_WinsAfterWorkerCleanup(bool asynchronous)
        {
            using CancellationTokenSource caller = new();
            TestObserver observer = new() { OnPhase = (phase, _, _) =>
            {
                if (phase == PrimeGenerationPhase.Stopping) caller.Cancel();
            }};
            Task<BigInteger> task = StartGeneration(asynchronous, 2, 2, _ => bytes => bytes.Clear(), caller.Token, observer: observer);
            var thrown = await Assert.ThrowsAsync<OperationCanceledException>(() => task.WaitAsync(TestTimeout));
            Assert.AreEqual(caller.Token, thrown.CancellationToken);
            Assert.IsTrue(task.IsCanceled);
        }

        private static PrimeGenerationContext ReadyContext(int workers, CancellationToken token = default)
        {
            PrimeGenerationContext context = new(token, workers);
            for (int worker = 0; worker < workers; worker++) context.WorkerReady(worker);
            context.MarkScheduledAll();
            return context;
        }

        private static void PublishKnown(PrimeGenerationContext context, BigInteger prime)
        {
            Assert.IsTrue(context.Acquire(0, out PrimeAdmissionTicket ticket, false));
            context.CompleteSearch(ticket, PreparationOutcome.KnownPrime, prime);
        }

        internal sealed class TestObserver : IPrimeGenerationObserver
        {
            internal Action<int>? OnReady;
            internal Action<int, long, long>? OnSearch;
            internal Action<int, long, int, long>? OnRound;
            internal Action<PrimeGenerationPhase, long, long>? OnPhase;
            internal Action<long>? OnRetire;
            public void WorkerReady(int index) => OnReady?.Invoke(index);
            public void SearchJobAdmitted(int index, long epoch, long admission) => OnSearch?.Invoke(index, epoch, admission);
            public void RoundAdmitted(int index, long epoch, int round, long admission) => OnRound?.Invoke(index, epoch, round, admission);
            public void PhaseChanged(PrimeGenerationPhase phase, long epoch, long sequence) => OnPhase?.Invoke(phase, epoch, sequence);
            public void EpochRetiring(long epoch) => OnRetire?.Invoke(epoch);
        }

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
