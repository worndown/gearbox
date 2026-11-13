using System.Numerics;
using Gearbox.Cryptography;
using static Gearbox.Tests.Cryptography.PrimeParallelTests;

namespace Gearbox.Tests.Cryptography;

[TestClass]
[DoNotParallelize]
public class PrimeGenerationContextTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(10);

    private static PreparedCandidate Prepare(int prime = 8191)
    {
        Assert.AreEqual(PreparationOutcome.NeedsRandomRounds, Prime.PrepareCandidate(prime, default, out var prepared));
        return prepared!;
    }

    private static PrimeGenerationContext Ready(int workers, CancellationToken token = default,
        IPrimeGenerationObserver? observer = null)
    {
        PrimeGenerationContext context = new(token, workers, observer);
        for (int worker = 0; worker < workers; worker++) context.WorkerReady(worker);
        context.MarkScheduledAll();
        return context;
    }

    private static PrimeAdmissionTicket Admit(PrimeGenerationContext context, int worker)
    {
        Assert.IsTrue(context.Acquire(worker, out var ticket, false));
        return ticket;
    }

    private static ValidationEpoch Promote(PrimeGenerationContext context, PreparedCandidate? candidate = null)
    {
        var ticket = Admit(context, 0);
        context.CompleteSearch(ticket, PreparationOutcome.NeedsRandomRounds, prepared: candidate ?? Prepare());
        Assert.AreEqual(PrimeGenerationPhase.Validating, context.Snapshot().Phase);
        var round = Admit(context, 0);
        var epoch = (ValidationEpoch)round.Epoch;
        context.CompleteRound(round, true);
        return epoch;
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void G0_RequiresBothReadinessAndSuccessfulScheduling(bool scheduleFirst)
    {
        using var context = new PrimeGenerationContext(default, 2);
        if (scheduleFirst) context.MarkScheduledAll();
        context.WorkerReady(0);
        context.WorkerReady(0); // Readiness is idempotent.
        Assert.AreEqual(1, context.Snapshot().ReadyWorkers);
        Assert.IsFalse(context.Acquire(0, out _, false));
        context.WorkerReady(1);
        if (!scheduleFirst)
        {
            Assert.IsFalse(context.Acquire(0, out _, false));
            context.MarkScheduledAll();
        }
        Assert.AreEqual(PrimeGenerationPhase.Searching, context.Snapshot().Phase);
        Assert.AreEqual(1L, context.Snapshot().TransitionSequence);
        context.MarkScheduledAll();
        Assert.AreEqual(1L, context.Snapshot().TransitionSequence);
        context.Fail(new Exception("Test shutdown."));
    }

    [TestMethod]
    public async Task G1_G2_G3_SimultaneousPromotionsSelectOneAndDrainAdmittedJobs()
    {
        using var context = Ready(3);
        var first = Admit(context, 0);
        var second = Admit(context, 1);
        var blocked = Admit(context, 2);
        Assert.IsFalse(context.Acquire(0, out _, false), "A busy worker cannot obtain a second ticket.");
        using Barrier barrier = new(2);
        PreparedCandidate[] candidates = [Prepare(8191), Prepare(1009)];
        Task[] promotions = new[] { first, second }.Select((ticket, i) => Task.Run(() =>
        {
            Assert.IsTrue(barrier.SignalAndWait(Deadline));
            context.CompleteSearch(ticket, PreparationOutcome.NeedsRandomRounds, prepared: candidates[i]);
        })).ToArray();
        await Task.WhenAll(promotions).WaitAsync(Deadline);
        var draining = context.Snapshot();
        Assert.AreEqual(PrimeGenerationPhase.DrainingSearch, draining.Phase);
        Assert.IsTrue(candidates.Any(candidate => candidate.Candidate == draining.PendingCandidate));
        Assert.AreEqual(1, draining.ActiveJobs);
        Assert.IsFalse(context.Acquire(0, out _, false));
        Assert.IsFalse(context.Completed.IsSet);
        // A stale known-prime completion cannot publish or replace the selected candidate.
        context.CompleteSearch(blocked, PreparationOutcome.KnownPrime, 3);
        Assert.AreEqual(PrimeGenerationPhase.Validating, context.Snapshot().Phase);
        Assert.AreEqual(draining.PendingCandidate, context.Snapshot().PendingCandidate);
        Assert.IsNull(context.Snapshot().Result);
        context.Fail(new Exception("Test shutdown."));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task G3_G6_WaitForCloseCancellationToReturn(bool rejection)
    {
        using var context = Ready(2);
        PrimeAdmissionTicket ticket;
        if (rejection)
        {
            Promote(context);
            ticket = Admit(context, 0);
        }
        else ticket = Admit(context, 0);
        using ManualResetEventSlim entered = new(false);
        using ManualResetEventSlim release = new(false);
        using var registration = ticket.Epoch.Token.Register(() =>
        {
            entered.Set();
            Assert.IsTrue(release.Wait(Deadline));
        });
        Task closing = Task.Run(() =>
        {
            if (rejection) context.CompleteRound(ticket, false);
            else context.CompleteSearch(ticket, PreparationOutcome.NeedsRandomRounds, prepared: Prepare());
        });
        try
        {
            Assert.IsTrue(entered.Wait(Deadline));
            Assert.AreEqual(rejection ? PrimeGenerationPhase.DrainingValidation : PrimeGenerationPhase.DrainingSearch,
                context.Snapshot().Phase);
            Assert.AreEqual(ticket.Epoch.Id, context.Snapshot().EpochId);
            Assert.AreEqual(0, context.Snapshot().ActiveJobs);
            Assert.IsFalse(context.Acquire(1, out _, false));
        }
        finally { release.Set(); }
        await closing.WaitAsync(Deadline);
        Assert.AreEqual(rejection ? PrimeGenerationPhase.Searching : PrimeGenerationPhase.Validating, context.Snapshot().Phase);
        Assert.IsTrue(context.Snapshot().EpochId > ticket.Epoch.Id);
        context.Fail(new Exception("Test shutdown."));
    }

    [TestMethod]
    public void G4_G7_ExhaustedIndicesAndOutOfOrderCompletionsRequireAll64Passes()
    {
        using var context = Ready(65);
        var epoch = Promote(context);
        PrimeAdmissionTicket[] tickets = Enumerable.Range(0, 63).Select(worker => Admit(context, worker)).ToArray();
        CollectionAssert.AreEqual(Enumerable.Range(1, 63).ToArray(), tickets.Select(ticket => ticket.RoundIndex).ToArray());
        Assert.IsFalse(context.Acquire(64, out _, false));
        context.CompleteRound(tickets[^1], true); // Round 63 finishes ahead of earlier rounds.
        Assert.IsFalse(context.Completed.IsSet);
        Assert.IsNull(context.Snapshot().Result);
        context.CompleteRound(tickets[^1], false); // Duplicate cannot reject or change accounting.
        Assert.AreEqual(2, epoch.PassedRounds);
        for (int i = tickets.Length - 2; i >= 0; i--) context.CompleteRound(tickets[i], true);
        Assert.AreEqual(64, epoch.PassedRounds);
        Assert.AreEqual(0, epoch.ActiveRounds);
        Assert.IsTrue(epoch.RoundStates.All(state => state == 2));
        Assert.AreEqual(new BigInteger(8191), context.GetResult(default));
        Assert.IsFalse(context.Acquire(0, out _, false));
    }

    [TestMethod]
    public void G5_G6_RepeatedActualRejectionAndStaleReports_100Iterations()
    {
        using var context = Ready(3);
        // This fixture deliberately bypasses preparation only in context tests, using a real MR witness.
        PreparedCandidate composite = new(2047, 1023, 1, 2044, 2, 7);
        long previousId = 0;
        for (int iteration = 0; iteration < 100; iteration++)
        {
            var search = Admit(context, 0);
            var staleSearch = Admit(context, 1);
            context.CompleteSearch(search, PreparationOutcome.NeedsRandomRounds, prepared: composite);
            Assert.IsFalse(context.Acquire(2, out _, false));
            context.CompleteSearch(staleSearch, PreparationOutcome.NeedsRandomRounds, prepared: Prepare());
            var reject = Admit(context, 0);
            var active = Admit(context, 1);
            var validation = (ValidationEpoch)reject.Epoch;
            Assert.IsTrue(validation.Id > previousId);
            Assert.AreEqual(0, reject.RoundIndex);
            Assert.AreEqual(0, validation.PassedRounds);
            Assert.IsFalse(Prime.ValidateRandomRound(composite, new byte[2], bytes =>
            {
                bytes.Clear(); bytes[^1] = 1; // Witness 3 rejects 2047.
            }, validation.Token));
            context.CompleteRound(reject, false);
            Assert.AreEqual(PrimeGenerationPhase.DrainingValidation, context.Snapshot().Phase);
            Assert.IsTrue(validation.Token.IsCancellationRequested);
            Assert.IsFalse(context.Acquire(2, out _, false));
            context.CompleteRound(reject, true); // Duplicate is inert while draining.
            context.CompleteRound(active, null);
            Assert.AreEqual(PrimeGenerationPhase.Searching, context.Snapshot().Phase);
            Assert.IsNull(context.Snapshot().PendingCandidate);
            var newer = Admit(context, 0);
            var before = context.Snapshot();
            context.CompleteSearch(search, PreparationOutcome.KnownPrime, 2);
            context.CompleteRound(reject, false);
            Assert.AreEqual(before, context.Snapshot(), "Old reports cannot release a newer worker ticket.");
            Assert.IsFalse(newer.Epoch.Token.IsCancellationRequested);
            context.CompleteSearch(newer, PreparationOutcome.Composite);
            previousId = newer.Epoch.Id;
        }
        context.Fail(new Exception("Test shutdown."));
        Assert.AreEqual(0, context.Snapshot().ActiveJobs);
        Assert.AreEqual(0, context.Snapshot().TransitionOwners);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public async Task G8_CallerCancellationClosesEveryPhaseAndWakesWaiters(int targetValue)
    {
        PrimeGenerationPhase target = (PrimeGenerationPhase)targetValue;
        using CancellationTokenSource caller = new();
        using var context = new PrimeGenerationContext(caller.Token, 2);
        PrimeAdmissionTicket? unfinished = null;
        if (target != PrimeGenerationPhase.Starting)
        {
            context.WorkerReady(0); context.WorkerReady(1); context.MarkScheduledAll();
            if (target == PrimeGenerationPhase.DrainingSearch)
            {
                var promotion = Admit(context, 0);
                unfinished = Admit(context, 1);
                context.CompleteSearch(promotion, PreparationOutcome.NeedsRandomRounds, prepared: Prepare());
            }
            else if (target is PrimeGenerationPhase.Validating or PrimeGenerationPhase.DrainingValidation)
            {
                Promote(context);
                if (target == PrimeGenerationPhase.DrainingValidation)
                {
                    var reject = Admit(context, 0);
                    unfinished = Admit(context, 1);
                    context.CompleteRound(reject, false);
                }
            }
        }
        Assert.AreEqual(target, context.Snapshot().Phase);
        // Hold a worker's active slot to force a predicate wait even in admission phases.
        if (unfinished is null && target is PrimeGenerationPhase.Searching or PrimeGenerationPhase.Validating)
            unfinished = Admit(context, 1);
        Task<bool> waiter = Task.Run(() => context.Acquire(1, out _));
        caller.Cancel();
        Assert.IsFalse(await waiter.WaitAsync(Deadline));
        Assert.IsTrue(context.Completed.IsSet);
        Assert.IsFalse(context.Acquire(0, out _, false));
        if (unfinished is { } ticket)
        {
            if (ticket.Epoch is SearchEpoch) context.CompleteSearch(ticket, PreparationOutcome.KnownPrime, 2);
            else context.CompleteRound(ticket, true);
        }
        context.MarkScheduledAll(); context.WorkerReady(0);
        Assert.AreEqual(PrimeGenerationPhase.Stopping, context.Snapshot().Phase);
        Assert.AreEqual(caller.Token, Assert.ThrowsExactly<OperationCanceledException>(() => context.GetResult(caller.Token)).CancellationToken);
    }

    [TestMethod]
    public async Task G9_CancellationDuringTransitionOwnerWorkCannotReopenOrCompleteEarly()
    {
        using CancellationTokenSource caller = new();
        using ManualResetEventSlim entered = new(false);
        using ManualResetEventSlim release = new(false);
        TestObserver observer = new() { OnRetire = _ =>
        {
            entered.Set(); Assert.IsTrue(release.Wait(Deadline));
        }};
        using var context = Ready(2, caller.Token, observer);
        var search = Admit(context, 0);
        Task transition = Task.Run(() => context.CompleteSearch(search, PreparationOutcome.NeedsRandomRounds, prepared: Prepare()));
        try
        {
            Assert.IsTrue(entered.Wait(Deadline));
            Assert.AreEqual(PrimeGenerationPhase.DrainingSearch, context.Snapshot().Phase);
            Assert.AreEqual(search.Epoch.Id, context.Snapshot().EpochId);
            caller.Cancel();
            Assert.AreEqual(1, context.Snapshot().TransitionOwners);
            Assert.ThrowsExactly<InvalidOperationException>(() => context.GetResult(caller.Token));
            Assert.IsFalse(context.Acquire(1, out _, false));
        }
        finally { release.Set(); }
        await transition.WaitAsync(Deadline);
        Assert.AreEqual(0, context.Snapshot().TransitionOwners);
        Assert.AreEqual(PrimeGenerationPhase.Stopping, context.Snapshot().Phase);
        Assert.ThrowsExactly<OperationCanceledException>(() => context.GetResult(caller.Token));
    }

    [TestMethod]
    public async Task G3_RetirementHeldPreventsSuccessorAdmission()
    {
        using ManualResetEventSlim entered = new(false);
        using ManualResetEventSlim release = new(false);
        using var context = Ready(2, observer: new TestObserver { OnRetire = _ =>
        {
            entered.Set(); Assert.IsTrue(release.Wait(Deadline));
        }});
        var ticket = Admit(context, 0);
        Task transition = Task.Run(() => context.CompleteSearch(ticket, PreparationOutcome.NeedsRandomRounds, prepared: Prepare()));
        try
        {
            Assert.IsTrue(entered.Wait(Deadline));
            Assert.IsFalse(context.Acquire(1, out _, false));
            Assert.AreEqual(ticket.Epoch.Id, context.Snapshot().EpochId);
            Assert.AreEqual(PrimeGenerationPhase.DrainingSearch, context.Snapshot().Phase);
        }
        finally { release.Set(); }
        await transition.WaitAsync(Deadline);
        Assert.AreEqual(PrimeGenerationPhase.Validating, context.Snapshot().Phase);
        context.Fail(new Exception("Test shutdown."));
    }

    [TestMethod]
    public async Task RejectionRacingPeerCompletion_100BoundedTransitions()
    {
        using var context = Ready(2);
        using Barrier completion = new(2);
        for (int iteration = 0; iteration < 100; iteration++)
        {
            Promote(context);
            var reject = Admit(context, 0);
            var pass = Admit(context, 1);
            Task[] peers = new[] { (Ticket: reject, Passed: false), (Ticket: pass, Passed: true) }
                .Select(job => Task.Run(() =>
                {
                    Assert.IsTrue(completion.SignalAndWait(Deadline));
                    context.CompleteRound(job.Ticket, job.Passed);
                })).ToArray();
            await Task.WhenAll(peers).WaitAsync(Deadline);
            Assert.AreEqual(PrimeGenerationPhase.Searching, context.Snapshot().Phase);
            Assert.AreEqual(0, context.Snapshot().ActiveJobs);
            Assert.AreEqual(0, context.Snapshot().TransitionOwners);
            Assert.IsTrue(context.Snapshot().EpochId > reject.Epoch.Id);
            Assert.IsTrue(((ValidationEpoch)reject.Epoch).Rejected);
            var before = context.Snapshot();
            context.CompleteRound(pass, false);
            context.CompleteRound(reject, true);
            Assert.AreEqual(before, context.Snapshot());
        }
        context.Fail(new Exception("Test shutdown."));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void CancellationCallbackFaultDuringEpochCloseStopsInsteadOfReopening(bool reject)
    {
        using var context = Ready(2);
        if (reject) Promote(context);
        var ticket = Admit(context, 0);
        InvalidOperationException failure = new("Callback failure.");
        using var registration = ticket.Epoch.Token.Register(() => throw failure);
        if (reject) context.CompleteRound(ticket, false);
        else context.CompleteSearch(ticket, PreparationOutcome.NeedsRandomRounds, prepared: Prepare());
        Assert.AreEqual(PrimeGenerationPhase.Stopping, context.Snapshot().Phase);
        var thrown = Assert.ThrowsExactly<AggregateException>(() => context.GetResult(default));
        Assert.AreSame(failure, thrown.InnerException);
    }
}
