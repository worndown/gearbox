using System.Numerics;
using System.Runtime.ExceptionServices;

namespace Gearbox.Cryptography
{
    internal sealed class PrimeGenerationContext : IDisposable
    {
        private readonly object publicationLock = new object();
        private readonly CancellationTokenSource cancellation;
        private readonly CancellationTokenRegistration completionRegistration;
        private BigInteger? result;
        private ExceptionDispatchInfo? failure;

        public ManualResetEventSlim Completed { get; } = new ManualResetEventSlim(false);
        public CancellationToken CancellationToken => this.cancellation.Token;

        public PrimeGenerationContext(CancellationToken cancellationToken)
        {
            this.cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            this.completionRegistration = this.cancellation.Token.Register(static state =>
                ((ManualResetEventSlim)state!).Set(), this.Completed);
        }

        public bool TryPublish(BigInteger prime)
        {
            lock (this.publicationLock)
            {
                if (this.result.HasValue || this.failure is not null || this.cancellation.IsCancellationRequested)
                {
                    return false;
                }

                // BigInteger is a struct: publish it under a lock rather than racing assignments.
                this.result = prime;
            }

            this.Stop();
            return true;
        }

        public void Fail(Exception exception)
        {
            lock (this.publicationLock)
            {
                // A genuine failure is reported even if another worker has already won.
                this.failure ??= ExceptionDispatchInfo.Capture(exception);
            }

            this.Stop();
        }

        // Read only after all started workers have completed.
        public BigInteger GetResult(CancellationToken callerCancellationToken)
        {
            callerCancellationToken.ThrowIfCancellationRequested();
            this.failure?.Throw();
            return this.result ?? throw new InvalidOperationException("Prime generation finished without a result.");
        }

        public void Dispose()
        {
            this.completionRegistration.Dispose();
            this.cancellation.Dispose();
            this.Completed.Dispose();
        }

        private void Stop()
        {
            this.Completed.Set();
            // Invoke cancellation callbacks outside the publication lock.
            this.cancellation.Cancel();
        }
    }
}
