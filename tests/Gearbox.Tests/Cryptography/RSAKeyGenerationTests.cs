using System.Numerics;
using System.Security.Cryptography;
using Gearbox.Cryptography;

namespace Gearbox.Tests.Cryptography
{
    public class RSAKeyGeneratorTests
    {
        [TestMethod]
        [DataRow(int.MinValue)]
        [DataRow(0)]
        [DataRow(1024)]
        [DataRow(2047)]
        [DataRow(2049)]
        [DataRow(16385)]
        [DataRow(int.MaxValue)]
        public void Generate_InvalidSize_ThrowsSynchronouslyEvenWhenCanceled(int bitLength)
        {
            CancellationToken token = new CancellationToken(true);
            ArgumentOutOfRangeException sync = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RSAKeyGenerator.Generate(bitLength, token));
            ArgumentOutOfRangeException async = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RSAKeyGenerator.GenerateAsync(bitLength, token));
            Assert.AreEqual("bitLength", sync.ParamName);
            Assert.AreEqual("bitLength", async.ParamName);
        }

        [TestMethod]
        [DataRow(2048)]
        [DataRow(16384)]
        public async Task Generate_PreCanceledToken_PreservesCallerToken(int bitLength)
        {
            CancellationToken token = new CancellationToken(true);
            OperationCanceledException sync = Assert.ThrowsExactly<OperationCanceledException>(() => RSAKeyGenerator.Generate(bitLength, token));
            Task<RSA> task = RSAKeyGenerator.GenerateAsync(bitLength, token);
            Assert.IsTrue(task.IsCanceled);
            OperationCanceledException async = await Assert.ThrowsAsync<OperationCanceledException>(() => task);
            Assert.AreEqual(token, sync.CancellationToken);
            Assert.AreEqual(token, async.CancellationToken);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_PreCanceledToken_DoesNotSearchAndDisposesProvider(bool asynchronous)
        {
            CapturingRsa provider = new CapturingRsa();
            CancellationToken token = new CancellationToken(true);
            await Assert.ThrowsAsync<OperationCanceledException>(() => GenerateWithPrimes(asynchronous,
                (_, _) => throw new AssertFailedException("A pre-canceled request searched for a prime."), provider, token));
            Assert.AreEqual(0, provider.ImportCount);
            Assert.AreEqual(1, provider.DisposeCount);
        }

        [TestMethod]
        [DataRow(2048, 16384, 8, 2056, true)]
        [DataRow(2048, 16384, 64, 2056, false)]
        [DataRow(3072, 3072, 0, 3072, true)]
        [DataRow(3072, 3072, 0, 2048, false)]
        public async Task Generate_UsesProviderSizeRules(int minimum, int maximum, int increment, int bitLength, bool supported)
        {
            CancellationToken token = new CancellationToken(true);
            foreach (bool asynchronous in new[] { false, true })
            {
                CapturingRsa provider = new CapturingRsa { Sizes = [new KeySizes(minimum, maximum, increment)] };
                Func<int, CancellationToken, BigInteger> source = (_, _) => throw new AssertFailedException("Validation searched for a prime.");
                if (supported)
                {
                    OperationCanceledException exception = asynchronous
                        ? await Assert.ThrowsAsync<OperationCanceledException>(() => RSAKeyGenerator.GenerateAsync(bitLength,
                            (bits, caller) => Task.FromResult(source(bits, caller)), provider, token))
                        : Assert.ThrowsExactly<OperationCanceledException>(() => RSAKeyGenerator.Generate(bitLength, source, provider, token));
                    Assert.AreEqual(token, exception.CancellationToken);
                }
                else
                {
                    ArgumentOutOfRangeException exception = asynchronous
                        ? Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RSAKeyGenerator.GenerateAsync(bitLength,
                            (bits, caller) => Task.FromResult(source(bits, caller)), provider, token))
                        : Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RSAKeyGenerator.Generate(bitLength, source, provider, token));
                    Assert.AreEqual("bitLength", exception.ParamName);
                }

                Assert.AreEqual(1, provider.DisposeCount);
                Assert.AreEqual(0, provider.ImportCount);
            }
        }

        [TestMethod]
        [DataRow(false, "p-exponent")]
        [DataRow(true, "p-exponent")]
        [DataRow(false, "q-exponent")]
        [DataRow(true, "q-exponent")]
        [DataRow(false, "duplicate")]
        [DataRow(true, "duplicate")]
        [DataRow(false, "close")]
        [DataRow(true, "close")]
        [DataRow(false, "separation-boundary")]
        [DataRow(true, "separation-boundary")]
        [DataRow(false, "short-modulus")]
        [DataRow(true, "short-modulus")]
        public async Task Generate_RejectedCandidates_RetriesCorrectPrimes(bool asynchronous, string scenario)
        {
            BigInteger p = UnsignedInteger(RSATestKey.RsaKey2048.P);
            BigInteger q = UnsignedInteger(RSATestKey.RsaKey2048.Q);
            BigInteger incompatible = 2 * 65537 * (p / (2 * 65537)) + 1;
            BigInteger separation = BigInteger.One << 924;
            // Composite stand-ins exercise only rejected paths; the accepted pair uses known primes.
            BigInteger lowP = (BigInteger.One << 1023) + 1;
            BigInteger lowQ = lowP + separation + 2;
            BigInteger closeQ = p - 2;
            BigInteger boundaryQ = p + separation;
            Assert.AreEqual(BigInteger.One, BigInteger.GreatestCommonDivisor(65537, lowP - 1));
            Assert.AreEqual(BigInteger.One, BigInteger.GreatestCommonDivisor(65537, lowQ - 1));
            Assert.AreEqual(BigInteger.One, BigInteger.GreatestCommonDivisor(65537, closeQ - 1));
            Assert.AreEqual(BigInteger.One, BigInteger.GreatestCommonDivisor(65537, boundaryQ - 1));
            Assert.AreEqual(2047L, (lowP * lowQ).GetBitLength());

            Queue<BigInteger> candidates = new Queue<BigInteger>(scenario switch
            {
                "p-exponent" => [incompatible, p, q],
                "q-exponent" => [p, incompatible, q],
                "duplicate" => [p, p, q],
                "close" => [p, closeQ, q],
                "separation-boundary" => [p, boundaryQ, q],
                "short-modulus" => [lowP, lowQ, p, q],
                _ => throw new AssertFailedException("Unknown scenario.")
            });
            int expectedCalls = candidates.Count;
            int calls = 0;
            CapturingRsa provider = new CapturingRsa();
            using RSA key = await GenerateWithPrimes(asynchronous, (bits, _) =>
            {
                Assert.AreEqual(1024, bits);
                Assert.IsTrue(candidates.Count > 0, "Unexpected extra prime search.");
                calls++;
                return candidates.Dequeue();
            }, provider);

            Assert.AreEqual(expectedCalls, calls);
            Assert.AreSame(provider, key);
            Assert.AreEqual(1, provider.ImportCount);
            Assert.AreEqual(0, provider.DisposeCount);
            AssertParametersCleared(provider.ImportedParameters);
            CompareRsaParameters(RSATestKey.RsaKey2048, key.ExportParameters(true));
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_PublicFactories_ProduceUsableExactWidthKeys(bool asynchronous)
        {
            using RSA key = asynchronous ? await RSAKeyGenerator.GenerateAsync(2048) : RSAKeyGenerator.Generate(2048);
            AssertGeneratedKey(key, 2048);
            RSAParameters parameters = key.ExportParameters(true);
            string pem;
            try
            {
                pem = RSAKey.EncodeParametersPem(parameters);
                CollectionAssert.AreEqual(key.ExportRSAPrivateKey(), DecodePem(pem));
            }
            finally
            {
                foreach (byte[] bytes in ParameterArrays(parameters)) CryptographicOperations.ZeroMemory(bytes);
            }

            using RSA peer = RSA.Create();
            peer.ImportFromPem(pem);
            AssertGeneratedKey(peer, 2048);
            byte[] data = [1, 2, 3, 4, 5];
            byte[] signature = key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Assert.IsTrue(peer.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            signature = peer.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Assert.IsTrue(key.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            CollectionAssert.AreEqual(data, peer.Decrypt(key.Encrypt(data, RSAEncryptionPadding.OaepSHA256), RSAEncryptionPadding.OaepSHA256));
            CollectionAssert.AreEqual(data, key.Decrypt(peer.Encrypt(data, RSAEncryptionPadding.OaepSHA256), RSAEncryptionPadding.OaepSHA256));
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_Success_ReturnsOwnedProviderUntilCallerDisposes(bool asynchronous)
        {
            CapturingRsa provider = new CapturingRsa();
            Queue<BigInteger> primes = FixturePrimes();
            using (RSA key = await GenerateWithPrimes(asynchronous, (_, _) => primes.Dequeue(), provider))
            {
                Assert.AreSame(provider, key);
                Assert.AreEqual(0, provider.DisposeCount);
                Assert.AreEqual(1, provider.ImportCount);
                AssertParametersCleared(provider.ImportedParameters);
                CompareRsaParameters(RSATestKey.RsaKey2048, key.ExportParameters(true));
            }

            Assert.AreEqual(1, provider.DisposeCount);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void Generate_NullPrimeDelegate_ThrowsSynchronouslyAndDisposesProvider(bool asynchronous)
        {
            CapturingRsa provider = new CapturingRsa();
            ArgumentNullException exception = asynchronous
                ? Assert.ThrowsExactly<ArgumentNullException>(() => RSAKeyGenerator.GenerateAsync(2048, null!, provider))
                : Assert.ThrowsExactly<ArgumentNullException>(() => RSAKeyGenerator.Generate(2048, null!, provider));
            Assert.AreEqual("generatePrime", exception.ParamName);
            Assert.AreEqual(0, provider.ImportCount);
            Assert.AreEqual(1, provider.DisposeCount);
        }

        [TestMethod]
        public async Task GenerateAsync_AwaitsPrimesSequentiallyWithoutCapturingContext()
        {
            TaskCompletionSource<BigInteger> first = new TaskCompletionSource<BigInteger>(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource<BigInteger> second = new TaskCompletionSource<BigInteger>(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource qEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            CapturingRsa provider = new CapturingRsa();
            int calls = 0;
            CountingSynchronizationContext context = new CountingSynchronizationContext();
            SynchronizationContext? previous = SynchronizationContext.Current;
            Task<RSA> generation;
            try
            {
                SynchronizationContext.SetSynchronizationContext(context);
                generation = RSAKeyGenerator.GenerateAsync(2048, (bits, _) =>
                {
                    Assert.AreEqual(1024, bits);
                    if (Interlocked.Increment(ref calls) == 1) return first.Task;
                    Assert.AreEqual(2, calls, "Unexpected overlapping or repeated search.");
                    qEntered.SetResult();
                    return second.Task;
                }, provider);
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(previous);
            }

            Assert.AreEqual(1, calls);
            Assert.IsFalse(generation.IsCompleted);
            first.SetResult(UnsignedInteger(RSATestKey.RsaKey2048.P));
            await qEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.AreEqual(2, calls);
            Assert.IsFalse(generation.IsCompleted);
            second.SetResult(UnsignedInteger(RSATestKey.RsaKey2048.Q));
            using RSA key = await generation.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.AreSame(provider, key);
            Assert.AreEqual(0, context.PostCount);
            AssertParametersCleared(provider.ImportedParameters);
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(2)]
        public async Task GenerateAsync_PrimeTaskFailure_PropagatesAndDisposesProvider(int failAtCall)
        {
            TaskCompletionSource<BigInteger> search = new TaskCompletionSource<BigInteger>(TaskCreationOptions.RunContinuationsAsynchronously);
            CapturingRsa provider = new CapturingRsa();
            CryptographicException failure = new CryptographicException("Prime task failed.");
            int calls = 0;
            Task<RSA> generation = RSAKeyGenerator.GenerateAsync(2048, (_, _) =>
                ++calls == failAtCall ? search.Task : Task.FromResult(UnsignedInteger(RSATestKey.RsaKey2048.P)), provider);
            Assert.AreEqual(failAtCall, calls);
            Assert.IsFalse(generation.IsCompleted);
            Assert.AreEqual(0, provider.DisposeCount);

            search.SetException(failure);
            CryptographicException exception = await Assert.ThrowsExactlyAsync<CryptographicException>(() => generation.WaitAsync(TimeSpan.FromSeconds(10)));
            Assert.AreSame(failure, exception);
            Assert.IsTrue(generation.IsFaulted);
            Assert.AreEqual(0, provider.ImportCount);
            Assert.AreEqual(1, provider.DisposeCount);
        }

        [TestMethod]
        public async Task GenerateAsync_Cancellation_WaitsForActivePrimeSearchToFinish()
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            TaskCompletionSource<BigInteger> second = new TaskCompletionSource<BigInteger>(TaskCreationOptions.RunContinuationsAsynchronously);
            CapturingRsa provider = new CapturingRsa();
            int calls = 0;
            Task<RSA> generation = RSAKeyGenerator.GenerateAsync(2048, (_, token) =>
            {
                Assert.AreEqual(cancellation.Token, token);
                return ++calls == 1 ? Task.FromResult(UnsignedInteger(RSATestKey.RsaKey2048.P)) : second.Task;
            }, provider, cancellation.Token);
            Assert.AreEqual(2, calls);
            cancellation.Cancel();
            Assert.IsFalse(generation.IsCompleted, "Generation returned before the active prime search finished.");
            Assert.AreEqual(0, provider.DisposeCount);
            second.SetResult(UnsignedInteger(RSATestKey.RsaKey2048.Q));
            OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => generation.WaitAsync(TimeSpan.FromSeconds(10)));
            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.IsTrue(generation.IsCanceled);
            Assert.AreEqual(0, provider.ImportCount);
            Assert.AreEqual(1, provider.DisposeCount);
        }

        [TestMethod]
        [DataRow(false, 1)]
        [DataRow(true, 1)]
        [DataRow(false, 2)]
        [DataRow(true, 2)]
        [DataRow(false, 3)]
        [DataRow(true, 3)]
        public async Task Generate_CancellationDuringSearchOrRetry_DisposesProvider(bool asynchronous, int cancelAtCall)
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            CapturingRsa provider = new CapturingRsa();
            int calls = 0;
            BigInteger p = UnsignedInteger(RSATestKey.RsaKey2048.P);
            OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => GenerateWithPrimes(asynchronous,
                (_, token) =>
                {
                    Assert.AreEqual(cancellation.Token, token);
                    if (++calls == cancelAtCall) cancellation.Cancel();
                    return calls < 3 ? p : UnsignedInteger(RSATestKey.RsaKey2048.Q);
                }, provider, cancellation.Token));

            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.AreEqual(cancelAtCall, calls);
            Assert.AreEqual(0, provider.ImportCount);
            Assert.AreEqual(1, provider.DisposeCount);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_CancellationDuringImport_ClearsParametersAndDisposesKey(bool asynchronous)
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            CapturingRsa provider = new CapturingRsa { OnImport = _ => cancellation.Cancel() };
            Queue<BigInteger> primes = FixturePrimes();
            OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => GenerateWithPrimes(asynchronous,
                (_, _) => primes.Dequeue(), provider, cancellation.Token));
            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.AreEqual(1, provider.ImportCount);
            Assert.AreEqual(1, provider.DisposeCount);
            AssertParametersCleared(provider.ImportedParameters);
        }

        [TestMethod]
        [DataRow(false, 1)]
        [DataRow(true, 1)]
        [DataRow(false, 2)]
        [DataRow(true, 2)]
        public async Task Generate_PrimeSearchFailure_PropagatesAndDisposesProvider(bool asynchronous, int failAtCall)
        {
            CapturingRsa provider = new CapturingRsa();
            CryptographicException failure = new CryptographicException("Prime search failed.");
            int calls = 0;
            CryptographicException exception = await Assert.ThrowsExactlyAsync<CryptographicException>(() => GenerateWithPrimes(asynchronous,
                (_, _) => ++calls == failAtCall ? throw failure : UnsignedInteger(RSATestKey.RsaKey2048.P), provider));
            Assert.AreSame(failure, exception);
            Assert.AreEqual(failAtCall, calls);
            Assert.AreEqual(0, provider.ImportCount);
            Assert.AreEqual(1, provider.DisposeCount);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_ImportFailure_ClearsParametersAndDisposesProvider(bool asynchronous)
        {
            CryptographicException failure = new CryptographicException("Import failed.");
            CapturingRsa provider = new CapturingRsa { OnImport = _ => throw failure };
            Queue<BigInteger> primes = FixturePrimes();
            CryptographicException exception = await Assert.ThrowsExactlyAsync<CryptographicException>(() => GenerateWithPrimes(asynchronous,
                (_, _) => primes.Dequeue(), provider));
            Assert.AreSame(failure, exception);
            Assert.AreEqual(1, provider.DisposeCount);
            AssertParametersCleared(provider.ImportedParameters);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_DerivationFailure_DisposesProvider(bool asynchronous)
        {
            // Deliberately violate the internal delegate's prime contract to fail the modular inverse.
            BigInteger p = (BigInteger.One << 1024) - 1;
            BigInteger q = (BigInteger.One << 1024) - (BigInteger.One << 1020) - 3;
            Queue<BigInteger> candidates = new Queue<BigInteger>([p, q]);
            CapturingRsa provider = new CapturingRsa();
            ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() => GenerateWithPrimes(asynchronous,
                (_, _) => candidates.Dequeue(), provider));
            Assert.AreEqual("q", exception.ParamName);
            Assert.AreEqual(0, provider.ImportCount);
            Assert.AreEqual(1, provider.DisposeCount);
        }

        private static Task<RSA> GenerateWithPrimes(bool asynchronous, Func<int, CancellationToken, BigInteger> source,
            RSA provider, CancellationToken cancellationToken = default) => asynchronous
            ? RSAKeyGenerator.GenerateAsync(2048, (bits, token) => Task.FromResult(source(bits, token)), provider, cancellationToken)
            : Task.FromResult(RSAKeyGenerator.Generate(2048, source, provider, cancellationToken));

        private static Queue<BigInteger> FixturePrimes() => new Queue<BigInteger>(
            [UnsignedInteger(RSATestKey.RsaKey2048.P), UnsignedInteger(RSATestKey.RsaKey2048.Q)]);

        private static BigInteger UnsignedInteger(byte[]? bytes) => new BigInteger(bytes!, isUnsigned: true, isBigEndian: true);

        private static byte[][] ParameterArrays(RSAParameters parameters) =>
            [parameters.Modulus!, parameters.Exponent!, parameters.D!, parameters.P!, parameters.Q!, parameters.DP!, parameters.DQ!, parameters.InverseQ!];

        private static void AssertParametersCleared(RSAParameters parameters)
        {
            foreach (byte[] bytes in ParameterArrays(parameters))
            {
                Assert.IsNotNull(bytes);
                Assert.IsTrue(bytes.Length > 0);
                Assert.IsTrue(bytes.All(value => value == 0), "A generated parameter buffer was not cleared.");
            }
        }

        private static void AssertGeneratedKey(RSA key, int bitLength)
        {
            RSAParameters parameters = key.ExportParameters(true);
            try
            {
                BigInteger n = UnsignedInteger(parameters.Modulus);
                BigInteger p = UnsignedInteger(parameters.P);
                BigInteger q = UnsignedInteger(parameters.Q);
                BigInteger e = UnsignedInteger(parameters.Exponent);
                BigInteger d = UnsignedInteger(parameters.D);
                BigInteger phi = (p - 1) * (q - 1);
                BigInteger lambda = phi / BigInteger.GreatestCommonDivisor(p - 1, q - 1);
                Assert.AreEqual(bitLength, key.KeySize);
                Assert.AreEqual((long)bitLength, n.GetBitLength());
                Assert.AreEqual((long)bitLength / 2, p.GetBitLength());
                Assert.AreEqual((long)bitLength / 2, q.GetBitLength());
                Assert.AreEqual(new BigInteger(65537), e);
                CollectionAssert.AreEqual(new byte[] { 1, 0, 1 }, parameters.Exponent);
                Assert.AreNotEqual(p, q);
                Assert.IsTrue(BigInteger.Abs(p - q) > (BigInteger.One << (bitLength / 2 - 100)));
                Assert.AreEqual(n, p * q);
                Assert.AreEqual(BigInteger.One, e * d % lambda);
                Assert.AreEqual(d % (p - 1), UnsignedInteger(parameters.DP));
                Assert.AreEqual(d % (q - 1), UnsignedInteger(parameters.DQ));
                Assert.AreEqual(BigInteger.One, q * UnsignedInteger(parameters.InverseQ) % p);
                Assert.AreEqual(bitLength / 8, parameters.Modulus!.Length);
                Assert.AreEqual(bitLength / 8, parameters.D!.Length);
                foreach (byte[] bytes in new[] { parameters.P!, parameters.Q!, parameters.DP!, parameters.DQ!, parameters.InverseQ! })
                {
                    Assert.AreEqual(bitLength / 16, bytes.Length);
                }
            }
            finally
            {
                foreach (byte[] bytes in ParameterArrays(parameters)) CryptographicOperations.ZeroMemory(bytes);
            }
        }

        private static byte[] DecodePem(string pem)
        {
            PemFields fields = PemEncoding.Find(pem);
            return Convert.FromBase64String(pem[fields.Base64Data]);
        }

        private static void CompareRsaParameters(RSAParameters expected, RSAParameters actual)
        {
            Assert.IsTrue(actual.Modulus.SequenceEqual(expected.Modulus));
            Assert.IsTrue(actual.Exponent.SequenceEqual(expected.Exponent));
            Assert.IsTrue(actual.P.SequenceEqual(expected.P));
            Assert.IsTrue(actual.Q.SequenceEqual(expected.Q));
            Assert.IsTrue(actual.DP.SequenceEqual(expected.DP));
            Assert.IsTrue(actual.DQ.SequenceEqual(expected.DQ));
            Assert.IsTrue(actual.D.SequenceEqual(expected.D));
            Assert.IsTrue(actual.InverseQ.SequenceEqual(expected.InverseQ));
        }

        private sealed class CapturingRsa : RSA
        {
            private readonly RSA inner = RSA.Create();
            public KeySizes[]? Sizes { get; init; }
            public Action<RSAParameters>? OnImport { get; init; }
            public RSAParameters ImportedParameters { get; private set; }
            public int ImportCount { get; private set; }
            public int DisposeCount { get; private set; }
            public override int KeySize { get => this.inner.KeySize; set => this.inner.KeySize = value; }
            public override KeySizes[] LegalKeySizes => this.Sizes ?? this.inner.LegalKeySizes;
            public override RSAParameters ExportParameters(bool includePrivateParameters) => this.inner.ExportParameters(includePrivateParameters);

            public override void ImportParameters(RSAParameters parameters)
            {
                this.ImportedParameters = parameters;
                this.ImportCount++;
                this.OnImport?.Invoke(parameters);
                this.inner.ImportParameters(parameters);
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    this.DisposeCount++;
                    this.inner.Dispose();
                }

                base.Dispose(disposing);
            }
        }

        private sealed class CountingSynchronizationContext : SynchronizationContext
        {
            public int PostCount;
            public override void Post(SendOrPostCallback callback, object? state) => Interlocked.Increment(ref this.PostCount);
        }
    }
}
