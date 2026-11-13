using System.Numerics;
using System.Runtime.ExceptionServices;

namespace Gearbox.Cryptography;

internal enum PrimeGenerationPhase { Starting, Searching, DrainingSearch, Validating, DrainingValidation, Stopping }

internal interface IPrimeGenerationObserver
{
    void WorkerReady(int workerIndex);
    void SearchJobAdmitted(int workerIndex, long epochId, long admissionId);
    void RoundAdmitted(int workerIndex, long epochId, int roundIndex, long admissionId);
    void PhaseChanged(PrimeGenerationPhase phase, long epochId, long transitionSequence);
    void EpochRetiring(long epochId) { }
}

internal abstract class PrimeGenerationEpoch : IDisposable
{
    private readonly CancellationTokenSource cancellation;
    internal long Id { get; }
    internal CancellationToken Token { get; }
    internal bool CloseCancellationReturned;
    internal bool TransitionOwner;

    protected PrimeGenerationEpoch(long id, CancellationToken operationToken)
    {
        Id = id;
        cancellation = CancellationTokenSource.CreateLinkedTokenSource(operationToken);
        Token = cancellation.Token;
    }

    internal void Cancel() => cancellation.Cancel();
    public void Dispose() => cancellation.Dispose();
}

internal sealed class SearchEpoch(long id, CancellationToken operationToken) : PrimeGenerationEpoch(id, operationToken)
{
    internal int ActiveJobs;
}

internal sealed class ValidationEpoch(long id, PreparedCandidate candidate, CancellationToken operationToken)
    : PrimeGenerationEpoch(id, operationToken)
{
    internal PreparedCandidate Candidate { get; } = candidate;
    internal int NextRoundIndex;
    internal int ActiveRounds;
    internal int PassedRounds;
    internal bool Rejected;
    // 0: unclaimed, 1: active, 2: passed, 3: rejected/canceled.
    internal byte[] RoundStates { get; } = new byte[Prime.RandomMillerRabinRounds];
}

internal readonly record struct PrimeAdmissionTicket(PrimeGenerationEpoch Epoch, int WorkerIndex,
    long AdmissionId, int RoundIndex = -1);

internal readonly record struct PrimeGenerationSnapshot(PrimeGenerationPhase Phase, long EpochId,
    int ReadyWorkers, bool ScheduledAll, int ActiveJobs, int NextRoundIndex, int PassedRounds,
    BigInteger? PendingCandidate, BigInteger? Result, int TransitionOwners, long TransitionSequence);

internal sealed class PrimeGenerationContext : IDisposable
{
    // Gates share one monitor. Work, callbacks and resource retirement never hold it.
    private readonly object stateLock = new();
    private readonly CancellationTokenSource cancellation;
    private readonly CancellationTokenRegistration completionRegistration;
    private readonly IPrimeGenerationObserver? observer;
    private readonly bool[] ready;
    private readonly PrimeAdmissionTicket?[] active;
    private PrimeGenerationEpoch? epoch;
    private PreparedCandidate? pending;
    private PrimeGenerationPhase phase = PrimeGenerationPhase.Starting;
    private bool scheduledAll;
    private int readyWorkers;
    private long nextEpochId = 1;
    private long nextAdmissionId;
    private long transitionSequence;
    private int transitionOwners;
    private BigInteger? result;
    private ExceptionDispatchInfo? failure;

    public ManualResetEventSlim Completed { get; } = new(false);
    public CancellationToken CancellationToken { get; }

    internal PrimeGenerationContext(CancellationToken callerToken, int workerCount,
        IPrimeGenerationObserver? observer = null)
    {
        this.observer = observer;
        ready = new bool[workerCount];
        active = new PrimeAdmissionTicket?[workerCount];
        cancellation = CancellationTokenSource.CreateLinkedTokenSource(callerToken);
        CancellationToken = cancellation.Token;
        // G0's initial epoch is allocated outside the monitor before scheduling starts.
        epoch = new SearchEpoch(1, CancellationToken);
        completionRegistration = CancellationToken.Register(static state =>
            ((PrimeGenerationContext)state!).OnOperationCanceled(), this);
    }

    private bool Running => phase != PrimeGenerationPhase.Stopping &&
        !CancellationToken.IsCancellationRequested && result is null && failure is null;

    private readonly record struct PhaseNotice(PrimeGenerationPhase Phase, long EpochId, long Sequence);

    private PhaseNotice ChangePhase(PrimeGenerationPhase next)
    {
        phase = next;
        Monitor.PulseAll(stateLock);
        return new(next, epoch?.Id ?? 0, ++transitionSequence);
    }

    private void Notify(PhaseNotice? notice)
    {
        if (observer is null || notice is not { } value) return;
        Observe(() => observer.PhaseChanged(value.Phase, value.EpochId, value.Sequence));
    }

    private void Observe(Action callback)
    {
        try { callback(); }
        catch (Exception exception) { Fail(exception); }
    }

    internal void WorkerReady(int workerIndex)
    {
        bool notify = false;
        lock (stateLock)
        {
            if (!ready[workerIndex] && Running)
            {
                ready[workerIndex] = true;
                readyWorkers++;
                notify = true;
            }
        }
        if (notify && observer is not null) Observe(() => observer.WorkerReady(workerIndex));
        OpenStartup();
    }

    internal void MarkScheduledAll()
    {
        lock (stateLock) scheduledAll = true;
        OpenStartup();
    }

    private void OpenStartup()
    {
        PhaseNotice? notice = null;
        lock (stateLock)
        {
            // G0: all configured tasks scheduled and initialized; faults break startup.
            if (phase == PrimeGenerationPhase.Starting && scheduledAll && readyWorkers == ready.Length && Running)
                notice = ChangePhase(PrimeGenerationPhase.Searching);
        }
        Notify(notice);
    }

    internal bool Acquire(int workerIndex, out PrimeAdmissionTicket ticket, bool wait = true)
    {
        lock (stateLock)
        {
            while (Running)
            {
                if (active[workerIndex] is null)
                {
                    if (phase == PrimeGenerationPhase.Searching && epoch is SearchEpoch search && !search.Token.IsCancellationRequested)
                    {
                        // G1: ticket and active-job count change atomically.
                        ticket = new(search, workerIndex, ++nextAdmissionId);
                        active[workerIndex] = ticket;
                        search.ActiveJobs++;
                        return true;
                    }
                    if (phase == PrimeGenerationPhase.Validating && epoch is ValidationEpoch validation &&
                        !validation.Rejected && validation.NextRoundIndex < Prime.RandomMillerRabinRounds)
                    {
                        // G4: exactly 64 distinct indices; idle workers wait when exhausted.
                        int round = validation.NextRoundIndex++;
                        ticket = new(validation, workerIndex, ++nextAdmissionId, round);
                        active[workerIndex] = ticket;
                        validation.RoundStates[round] = 1;
                        validation.ActiveRounds++;
                        return true;
                    }
                }
                if (!wait) break;
                Monitor.Wait(stateLock);
            }
        }
        ticket = default;
        return false;
    }

    internal void NotifyAdmission(PrimeAdmissionTicket ticket)
    {
        if (observer is null) return;
        // The worker invokes this inside its finally-protected job.
        if (ticket.Epoch is SearchEpoch)
            observer.SearchJobAdmitted(ticket.WorkerIndex, ticket.Epoch.Id, ticket.AdmissionId);
        else
            observer.RoundAdmitted(ticket.WorkerIndex, ticket.Epoch.Id, ticket.RoundIndex, ticket.AdmissionId);
    }

    private bool Matches(PrimeAdmissionTicket ticket) =>
        ticket.WorkerIndex >= 0 && ticket.WorkerIndex < active.Length &&
        active[ticket.WorkerIndex] is { } current && current == ticket;

    internal void CompleteSearch(PrimeAdmissionTicket ticket, PreparationOutcome outcome,
        BigInteger candidate = default, PreparedCandidate? prepared = null)
    {
        SearchEpoch? close = null;
        PhaseNotice? notice = null;
        bool stop = false;
        lock (stateLock)
        {
            if (ticket.Epoch is not SearchEpoch search || !Matches(ticket)) return;
            active[ticket.WorkerIndex] = null;
            search.ActiveJobs--;
            if (ReferenceEquals(epoch, search) && phase == PrimeGenerationPhase.Searching && Running)
            {
                if (outcome == PreparationOutcome.KnownPrime)
                {
                    // G7: only a current, matching search ticket can publish a known prime.
                    result = candidate;
                    notice = ChangePhase(PrimeGenerationPhase.Stopping);
                    stop = true;
                }
                else if (outcome == PreparationOutcome.NeedsRandomRounds && prepared is not null)
                {
                    // G2: the first promotion closes admission and appoints the close owner.
                    pending = prepared;
                    notice = ChangePhase(PrimeGenerationPhase.DrainingSearch);
                    close = search;
                }
            }
            Monitor.PulseAll(stateLock);
        }
        Notify(notice);
        if (stop) RequestStop();
        if (close is not null) CloseEpoch(close);
        else TryTransition(ticket.Epoch);
    }

    internal void CompleteRound(PrimeAdmissionTicket ticket, bool? passed)
    {
        ValidationEpoch? close = null;
        PhaseNotice? notice = null;
        bool stop = false;
        lock (stateLock)
        {
            if (ticket.Epoch is not ValidationEpoch validation || !Matches(ticket)) return;
            active[ticket.WorkerIndex] = null;
            validation.ActiveRounds--;
            validation.RoundStates[ticket.RoundIndex] = passed == true ? (byte)2 : (byte)3;
            if (passed == true) validation.PassedRounds++;
            if (ReferenceEquals(epoch, validation) && phase == PrimeGenerationPhase.Validating && Running && !validation.Rejected)
            {
                if (passed == false)
                {
                    // G5: rejection closes admission once; it is not an operation fault.
                    validation.Rejected = true;
                    notice = ChangePhase(PrimeGenerationPhase.DrainingValidation);
                    close = validation;
                }
                else if (validation.PassedRounds == Prime.RandomMillerRabinRounds && validation.ActiveRounds == 0)
                {
                    // G7: all 64 distinct completions passed, with no active round remaining.
                    result = validation.Candidate.Candidate;
                    notice = ChangePhase(PrimeGenerationPhase.Stopping);
                    stop = true;
                }
            }
            Monitor.PulseAll(stateLock);
        }
        Notify(notice);
        if (stop) RequestStop();
        if (close is not null) CloseEpoch(close);
        else TryTransition(ticket.Epoch);
    }

    private void CloseEpoch(PrimeGenerationEpoch old)
    {
        try { old.Cancel(); }
        catch (Exception exception) { Fail(exception); }
        finally
        {
            lock (stateLock)
            {
                old.CloseCancellationReturned = true;
                Monitor.PulseAll(stateLock);
            }
        }
        TryTransition(old);
    }

    private bool CanTransition(PrimeGenerationEpoch old) => Running && ReferenceEquals(epoch, old) &&
        old.CloseCancellationReturned &&
        ((phase == PrimeGenerationPhase.DrainingSearch && old is SearchEpoch { ActiveJobs: 0 } && pending is not null) ||
         (phase == PrimeGenerationPhase.DrainingValidation && old is ValidationEpoch { Rejected: true, ActiveRounds: 0 }));

    private void TryTransition(PrimeGenerationEpoch old)
    {
        long id;
        PreparedCandidate? candidate;
        lock (stateLock)
        {
            // G3/G6: zero admitted jobs and completed cancellation; elect one retirement owner.
            if (!CanTransition(old) || old.TransitionOwner) return;
            old.TransitionOwner = true;
            transitionOwners++;
            id = ++nextEpochId;
            candidate = old is SearchEpoch ? pending : null;
        }
        PrimeGenerationEpoch? successor = null;
        PhaseNotice? notice = null;
        try
        {
            observer?.EpochRetiring(old.Id);
            old.Dispose();
            successor = candidate is not null ? new ValidationEpoch(id, candidate, CancellationToken)
                : new SearchEpoch(id, CancellationToken);
            lock (stateLock)
            {
                // Termination can win during retirement: no phase may reopen after Stopping.
                if (CanTransition(old))
                {
                    epoch = successor;
                    successor = null;
                    if (candidate is null) pending = null;
                    notice = ChangePhase(candidate is null ? PrimeGenerationPhase.Searching : PrimeGenerationPhase.Validating);
                }
            }
            Notify(notice);
        }
        catch (Exception exception) { Fail(exception); }
        finally
        {
            try { successor?.Dispose(); }
            catch (Exception exception) { Fail(exception); }
            lock (stateLock)
            {
                transitionOwners--;
                Monitor.PulseAll(stateLock);
            }
        }
    }

    public void Fail(Exception exception)
    {
        ExceptionDispatchInfo captured = ExceptionDispatchInfo.Capture(exception);
        PhaseNotice? notice;
        lock (stateLock)
        {
            failure ??= captured; // Genuine faults after provisional publication still propagate.
            notice = phase == PrimeGenerationPhase.Stopping ? null : ChangePhase(PrimeGenerationPhase.Stopping);
        }
        Notify(notice);
        RequestStop();
    }

    private void OnOperationCanceled()
    {
        PhaseNotice? notice;
        lock (stateLock)
            notice = phase == PrimeGenerationPhase.Stopping ? null : ChangePhase(PrimeGenerationPhase.Stopping);
        Completed.Set(); // G8: phase handoffs never signal this event.
        Notify(notice);
    }

    private void RequestStop()
    {
        Completed.Set();
        try { cancellation.Cancel(); }
        catch (Exception exception)
        {
            ExceptionDispatchInfo captured = ExceptionDispatchInfo.Capture(exception);
            lock (stateLock) failure ??= captured;
        }
    }

    internal PrimeGenerationSnapshot Snapshot()
    {
        lock (stateLock)
            return new(phase, epoch?.Id ?? 0, readyWorkers, scheduledAll,
                epoch is SearchEpoch s ? s.ActiveJobs : epoch is ValidationEpoch v ? v.ActiveRounds : 0,
                epoch is ValidationEpoch v1 ? v1.NextRoundIndex : 0,
                epoch is ValidationEpoch v2 ? v2.PassedRounds : 0, pending?.Candidate, result,
                transitionOwners, transitionSequence);
    }

    // G9: invoke after every actually scheduled worker, including retirement owners, has joined.
    public BigInteger GetResult(CancellationToken callerToken)
    {
        lock (stateLock)
        {
            if (phase != PrimeGenerationPhase.Stopping || transitionOwners != 0 || active.Any(ticket => ticket is not null))
                throw new InvalidOperationException("Prime generation has not drained.");
        }
        callerToken.ThrowIfCancellationRequested();
        failure?.Throw();
        return result ?? throw new InvalidOperationException("Prime generation finished without a result.");
    }

    public void Dispose()
    {
        completionRegistration.Dispose(); // Wait for cancellation callbacks before their dependencies.
        epoch?.Dispose();
        cancellation.Dispose();
        Completed.Dispose();
    }
}
