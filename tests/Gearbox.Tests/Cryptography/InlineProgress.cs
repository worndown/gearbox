namespace Gearbox.Tests.Cryptography
{
    // Progress<T> dispatches callbacks asynchronously; cancellation tests need deterministic callbacks.
    internal sealed class InlineProgress(Action<int> report) : IProgress<int>
    {
        public void Report(int value) => report(value);
    }
}
