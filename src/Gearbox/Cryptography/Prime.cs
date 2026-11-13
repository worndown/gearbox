using System.Numerics;
using System.Security.Cryptography;

namespace Gearbox.Cryptography
{
    /// <summary>
    /// Generates exact-bit-length probable primes and tests integer primality.
    /// </summary>
    /// <remarks>
    /// Candidates that survive preliminary checks must pass base-2 Miller-Rabin,
    /// strong Lucas-Selfridge, and 64 additional random Miller-Rabin rounds.
    /// For each fixed composite, false acceptance is bounded by 2^-128; this is
    /// not a primality proof. Concurrent calls use independent operation-local state.
    /// Cancellation is checked between computational steps; a single BigInteger.ModPow
    /// call cannot be interrupted.
    /// Generation at 512 bits or above searches independently on dedicated workers,
    /// up to one per physical core per call. All workers finish before the call completes.
    /// </remarks>
    public static class Prime
    {
        private const int RandomMillerRabinRounds = 64;
        private const int ParallelGenerationBitLength = 512;

        private static readonly int[] SmallPrimes =
        [
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
            61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
            131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
            197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
            277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
            359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
            439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
            521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
            607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677,
            683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
            773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
            863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
            967, 971, 977, 983, 991, 997
        ];

        // An instance is supplied per operation, keeping deterministic tests isolated.
        internal delegate void RandomByteFiller(Span<byte> destination);

        /// <summary>
        /// Generates a probable prime with exactly the requested bit length.
        /// </summary>
        /// <param name="bitLength">Length in bits, at least two. Two-bit generation samples 2 and 3 equally.</param>
        /// <param name="cancellationToken">Cancellation checked between computational steps.</param>
        public static BigInteger Generate(int bitLength, CancellationToken cancellationToken = default)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(bitLength, 2);
            cancellationToken.ThrowIfCancellationRequested();
            int workerCount = GetGenerationWorkerCount(bitLength);
            return workerCount == 1
                ? Generate(bitLength, RandomNumberGenerator.Fill, cancellationToken)
                : Generate(bitLength, workerCount, static _ => RandomNumberGenerator.Fill, cancellationToken);
        }

        /// <summary>
        /// Generates a probable prime asynchronously, using dedicated parallel workers
        /// at 512 bits or above and the thread pool for smaller requests.
        /// </summary>
        /// <param name="bitLength">Length in bits, at least two.</param>
        /// <param name="cancellationToken">Cancellation checked between computational steps.</param>
        public static Task<BigInteger> GenerateAsync(int bitLength, CancellationToken cancellationToken = default)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(bitLength, 2);
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled<BigInteger>(cancellationToken);
            }

            int workerCount = GetGenerationWorkerCount(bitLength);
            return workerCount == 1
                ? GenerateAsync(bitLength, RandomNumberGenerator.Fill, cancellationToken)
                : GenerateAsync(bitLength, workerCount, static _ => RandomNumberGenerator.Fill, cancellationToken);
        }

        /// <summary>
        /// Tests an integer with Miller-Rabin and strong Lucas-Selfridge.
        /// </summary>
        /// <param name="candidate">The integer to test. Values below two are not prime.</param>
        /// <param name="cancellationToken">Cancellation checked between computational steps.</param>
        /// <returns>Whether the candidate is a probable prime.</returns>
        public static bool IsProbablePrime(BigInteger candidate, CancellationToken cancellationToken = default)
        {
            return IsProbablePrime(candidate, RandomNumberGenerator.Fill, cancellationToken);
        }

        /// <summary>
        /// Runs probable-primality testing on the thread pool.
        /// </summary>
        /// <param name="candidate">The integer to test. Values below two are not prime.</param>
        /// <param name="cancellationToken">Cancellation checked between computational steps.</param>
        public static Task<bool> IsProbablePrimeAsync(BigInteger candidate, CancellationToken cancellationToken = default)
        {
            return IsProbablePrimeAsync(candidate, RandomNumberGenerator.Fill, cancellationToken);
        }

        internal static BigInteger Generate(int bitLength, RandomByteFiller fillRandomBytes, CancellationToken cancellationToken)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(bitLength, 2);
            ArgumentNullException.ThrowIfNull(fillRandomBytes);
            return SearchForPrime(bitLength, fillRandomBytes, cancellationToken);
        }

        private static BigInteger SearchForPrime(int bitLength, RandomByteFiller fillRandomBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            byte[] bytes = new byte[((bitLength - 1) / 8) + 1];
            int usedBits = ((bitLength - 1) % 8) + 1;
            byte highByteMask = (byte)((1 << usedBits) - 1);
            byte highestBit = (byte)(1 << (usedBits - 1));

            try
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    fillRandomBytes(bytes);
                    cancellationToken.ThrowIfCancellationRequested();
                    bytes[0] = (byte)((bytes[0] & highByteMask) | highestBit);
                    if (bitLength > 2)
                    {
                        bytes[^1] |= 1;
                    }

                    BigInteger candidate = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
                    if (IsProbablePrimeCore(candidate, fillRandomBytes, cancellationToken))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        return candidate;
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }

        internal static Task<BigInteger> GenerateAsync(int bitLength, RandomByteFiller fillRandomBytes, CancellationToken cancellationToken)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(bitLength, 2);
            ArgumentNullException.ThrowIfNull(fillRandomBytes);
            return Task.Run(() => Generate(bitLength, fillRandomBytes, cancellationToken), cancellationToken);
        }

        internal static int GetGenerationWorkerCount(int bitLength) =>
            bitLength < ParallelGenerationBitLength ? 1 : ProcessorTopology.WorkerCount;

        // Explicit worker settings keep deterministic tests and benchmarks operation-local.
        internal static BigInteger Generate(int bitLength, int workerCount,
            Func<int, RandomByteFiller> randomSourceFactory, CancellationToken cancellationToken,
            TaskScheduler? workerScheduler = null)
        {
            ValidateGenerationWorkers(bitLength, workerCount, randomSourceFactory);
            cancellationToken.ThrowIfCancellationRequested();
            if (workerCount == 1)
            {
                return Generate(bitLength, randomSourceFactory(0), cancellationToken);
            }

            using PrimeGenerationContext context = new PrimeGenerationContext(cancellationToken);
            Task[] workers = StartGenerationWorkers(bitLength, workerCount, randomSourceFactory,
                context, workerScheduler ?? TaskScheduler.Default);
            context.Completed.Wait();
            Task.WhenAll(workers).GetAwaiter().GetResult();
            return context.GetResult(cancellationToken);
        }

        internal static Task<BigInteger> GenerateAsync(int bitLength, int workerCount,
            Func<int, RandomByteFiller> randomSourceFactory, CancellationToken cancellationToken,
            TaskScheduler? workerScheduler = null)
        {
            ValidateGenerationWorkers(bitLength, workerCount, randomSourceFactory);
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled<BigInteger>(cancellationToken);
            }

            if (workerCount == 1)
            {
                return Task.Run(() => Generate(bitLength, randomSourceFactory(0), cancellationToken), cancellationToken);
            }

            return GenerateParallelAsync(bitLength, workerCount, randomSourceFactory,
                cancellationToken, workerScheduler ?? TaskScheduler.Default);
        }

        private static void ValidateGenerationWorkers(int bitLength, int workerCount,
            Func<int, RandomByteFiller> randomSourceFactory)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(bitLength, 2);
            ArgumentOutOfRangeException.ThrowIfLessThan(workerCount, 1);
            ArgumentNullException.ThrowIfNull(randomSourceFactory);
        }

        private static Task<BigInteger> GenerateParallelAsync(int bitLength, int workerCount,
            Func<int, RandomByteFiller> randomSourceFactory, CancellationToken cancellationToken,
            TaskScheduler workerScheduler)
        {
            TaskCompletionSource<BigInteger> completion = new TaskCompletionSource<BigInteger>(TaskCreationOptions.RunContinuationsAsynchronously);
            _ = CompleteParallelGenerationAsync(bitLength, workerCount, randomSourceFactory,
                cancellationToken, workerScheduler, completion);
            return completion.Task;
        }

        private static async Task CompleteParallelGenerationAsync(int bitLength, int workerCount,
            Func<int, RandomByteFiller> randomSourceFactory, CancellationToken cancellationToken,
            TaskScheduler workerScheduler, TaskCompletionSource<BigInteger> completion)
        {
            try
            {
                BigInteger result;
                using (PrimeGenerationContext context = new PrimeGenerationContext(cancellationToken))
                {
                    Task[] workers = StartGenerationWorkers(bitLength, workerCount, randomSourceFactory, context, workerScheduler);
                    await Task.WhenAll(workers).ConfigureAwait(false);
                    result = context.GetResult(cancellationToken);
                }

                completion.SetResult(result);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                completion.SetCanceled(cancellationToken);
            }
            catch (Exception exception)
            {
                // An unrelated OperationCanceledException is a worker fault, not caller cancellation.
                completion.SetException(exception);
            }
        }

        private static Task[] StartGenerationWorkers(int bitLength, int workerCount,
            Func<int, RandomByteFiller> randomSourceFactory, PrimeGenerationContext context,
            TaskScheduler workerScheduler)
        {
            Task[] workers = new Task[workerCount];
            // Unstarted slots remain complete if scheduling fails or the operation stops early.
            Array.Fill(workers, Task.CompletedTask);
            try
            {
                for (int index = 0; index < workerCount && !context.CancellationToken.IsCancellationRequested; index++)
                {
                    int workerIndex = index;
                    workers[index] = Task.Factory.StartNew(
                        () => GenerateWorker(bitLength, workerIndex, randomSourceFactory, context),
                        CancellationToken.None, TaskCreationOptions.LongRunning, workerScheduler);
                }
            }
            catch (Exception exception)
            {
                context.Fail(exception);
            }

            return workers;
        }

        private static void GenerateWorker(int bitLength, int workerIndex,
            Func<int, RandomByteFiller> randomSourceFactory, PrimeGenerationContext context)
        {
            try
            {
                context.CancellationToken.ThrowIfCancellationRequested();
                RandomByteFiller fillRandomBytes = randomSourceFactory(workerIndex);
                ArgumentNullException.ThrowIfNull(fillRandomBytes);
                BigInteger prime = SearchForPrime(bitLength, fillRandomBytes, context.CancellationToken);
                context.TryPublish(prime);
            }
            catch (OperationCanceledException exception) when (
                context.CancellationToken.IsCancellationRequested && exception.CancellationToken == context.CancellationToken)
            {
                // A winner, caller cancellation, or a failed peer stops this search normally.
            }
            catch (Exception exception)
            {
                context.Fail(exception);
            }
        }

        internal static bool IsProbablePrime(BigInteger candidate, RandomByteFiller fillRandomBytes, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(fillRandomBytes);
            cancellationToken.ThrowIfCancellationRequested();
            bool result = IsProbablePrimeCore(candidate, fillRandomBytes, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }

        internal static Task<bool> IsProbablePrimeAsync(BigInteger candidate, RandomByteFiller fillRandomBytes, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(fillRandomBytes);
            return Task.Run(() => IsProbablePrime(candidate, fillRandomBytes, cancellationToken), cancellationToken);
        }

        private static bool IsProbablePrimeCore(BigInteger candidate, RandomByteFiller fillRandomBytes, CancellationToken cancellationToken)
        {
            if (candidate < 2)
            {
                return false;
            }
            if (candidate == 2 || candidate == 3)
            {
                return true;
            }
            if (candidate.IsEven)
            {
                return false;
            }
            foreach (int prime in SmallPrimes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (candidate == prime)
                {
                    return true;
                }

                if (candidate % prime == 0)
                {
                    return false;
                }
            }
            
            if (IsPerfectSquare(candidate, cancellationToken))
            {
                return false;
            }

            (BigInteger oddPart, int powerOfTwo) = SplitPowerOfTwo(candidate - 1, cancellationToken);
            if (!PassesMillerRabinRound(candidate, 2, oddPart, powerOfTwo, cancellationToken)
                || !PassesStrongLucas(candidate, cancellationToken))
            {
                return false;
            }

            BigInteger witnessRange = candidate - 3;
            byte[] witnessBytes = (witnessRange - 1).ToByteArray(isUnsigned: true, isBigEndian: true);
            int usedBits = BitOperations.Log2((uint)witnessBytes[0]) + 1;
            byte highByteMask = (byte)((1 << usedBits) - 1);
            try
            {
                for (int round = 0; round < RandomMillerRabinRounds; round++)
                {
                    BigInteger witness = SampleBelow(witnessRange, witnessBytes, highByteMask, fillRandomBytes, cancellationToken) + 2;
                    if (!PassesMillerRabinRound(candidate, witness, oddPart, powerOfTwo, cancellationToken))
                    {
                        return false;
                    }
                }

                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(witnessBytes);
            }
        }

        internal static BigInteger SampleBelow(BigInteger upperBound, byte[] bytes, byte highByteMask, RandomByteFiller fillRandomBytes, CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                fillRandomBytes(bytes);
                cancellationToken.ThrowIfCancellationRequested();
                bytes[0] &= highByteMask;
                BigInteger value = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
                if (value < upperBound)
                {
                    return value;
                }
            }
        }

        // Test a mathematical component without the trial-division filter.
        internal static bool IsMillerRabinProbablePrime(BigInteger candidate, BigInteger witness, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (candidate < 2 || candidate.IsEven)
            {
                return candidate == 2;
            }

            if (candidate == 3)
            {
                return true;
            }

            ArgumentOutOfRangeException.ThrowIfLessThan(witness, new BigInteger(2));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(witness, candidate - 2);
            
            (BigInteger oddPart, int powerOfTwo) = SplitPowerOfTwo(candidate - 1, cancellationToken);
            return PassesMillerRabinRound(candidate, witness, oddPart, powerOfTwo, cancellationToken);
        }

        private static bool PassesMillerRabinRound(BigInteger candidate, BigInteger witness, BigInteger oddPart, int powerOfTwo, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            BigInteger value = BigInteger.ModPow(witness, oddPart, candidate);
            cancellationToken.ThrowIfCancellationRequested();
            if (value.IsOne || value == candidate - 1)
            {
                return true;
            }

            for (int r = 1; r < powerOfTwo; r++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                value = value * value % candidate;
                cancellationToken.ThrowIfCancellationRequested();
                if (value == candidate - 1)
                {
                    return true;
                }

                if (value.IsOne)
                {
                    return false;
                }
            }

            return false;
        }

        internal static bool IsStrongLucasProbablePrime(BigInteger candidate, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (candidate < 2 || candidate.IsEven)
            {
                return candidate == 2;
            }

            // A square never has Jacobi(D, candidate) == -1, so reject it before searching.
            bool result = !IsPerfectSquare(candidate, cancellationToken) &&
                          PassesStrongLucas(candidate, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }

        private static bool PassesStrongLucas(BigInteger candidate, CancellationToken cancellationToken)
        {
            BigInteger discriminant = 5;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int symbol = JacobiSymbol(discriminant, candidate, cancellationToken);
                if (symbol == -1)
                {
                    break;
                }
                
                if (symbol == 0)
                {
                    BigInteger factor = BigInteger.GreatestCommonDivisor(discriminant, candidate);
                    cancellationToken.ThrowIfCancellationRequested();
                    if (factor > 1 && factor < candidate)
                    {
                        return false;
                    }
                }

                discriminant = discriminant > 0 ? -(discriminant + 2) : -discriminant + 2;
            }

            BigInteger q = (1 - discriminant) / 4;
            BigInteger qFactor = BigInteger.GreatestCommonDivisor(q, candidate);
            cancellationToken.ThrowIfCancellationRequested();
            if (!qFactor.IsOne)
            {
                return false;
            }

            (BigInteger oddPart, int powerOfTwo) = SplitPowerOfTwo(candidate + 1, cancellationToken);
            BigInteger u = 0;
            BigInteger v = 2;
            BigInteger qPower = 1;
            foreach (byte value in oddPart.ToByteArray(isUnsigned: true, isBigEndian: true))
            {
                for (int bit = 7; bit >= 0; bit--)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    // Double the sequence index: U_2k, V_2k, Q^(2k).
                    u = u * v % candidate;
                    v = Normalize(v * v - 2 * qPower, candidate);
                    qPower = qPower * qPower % candidate;
                    if ((value & (1 << bit)) != 0)
                    {
                        // P = 1. Both additions use the previous doubled U and V.
                        BigInteger nextU = HalveModulo(u + v, candidate);
                        v = HalveModulo(discriminant * u + v, candidate);
                        u = nextU;
                        qPower = Normalize(qPower * q, candidate);
                    }
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (u.IsZero || v.IsZero)
            {
                return true;
            }

            for (int r = 1; r < powerOfTwo; r++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                v = Normalize(v * v - 2 * qPower, candidate);
                qPower = qPower * qPower % candidate;
                cancellationToken.ThrowIfCancellationRequested();
                if (v.IsZero)
                {
                    return true;
                }
            }

            return false;
        }

        internal static int JacobiSymbol(BigInteger value, BigInteger modulus, CancellationToken cancellationToken = default)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(modulus, BigInteger.One);
            if (modulus.IsEven)
            {
                throw new ArgumentOutOfRangeException(nameof(modulus), "The Jacobi modulus must be odd.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            value = Normalize(value, modulus);
            int sign = 1;
            while (!value.IsZero)
            {
                cancellationToken.ThrowIfCancellationRequested();
                while (value.IsEven)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    value >>= 1;
                    BigInteger residue = modulus % 8;
                    if (residue == 3 || residue == 5)
                    {
                        sign = -sign;
                    }
                }

                (value, modulus) = (modulus, value);
                if (value % 4 == 3 && modulus % 4 == 3)
                {
                    sign = -sign;
                }

                value %= modulus;
            }

            cancellationToken.ThrowIfCancellationRequested();
            return modulus.IsOne ? sign : 0;
        }

        private static bool IsPerfectSquare(BigInteger candidate, CancellationToken cancellationToken)
        {
            // Integer Newton iteration starts above the square root and stops at its floor.
            int rootBits = checked((int)((candidate.GetBitLength() + 1) / 2));
            BigInteger root = BigInteger.One << rootBits;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                BigInteger next = (root + candidate / root) >> 1;
                cancellationToken.ThrowIfCancellationRequested();
                if (next >= root)
                {
                    return root * root == candidate;
                }

                root = next;
            }
        }

        private static (BigInteger OddPart, int PowerOfTwo) SplitPowerOfTwo(BigInteger value, CancellationToken cancellationToken)
        {
            int powerOfTwo = 0;
            while (value.IsEven)
            {
                cancellationToken.ThrowIfCancellationRequested();
                value >>= 1;
                powerOfTwo++;
            }

            return (value, powerOfTwo);
        }

        private static BigInteger Normalize(BigInteger value, BigInteger modulus)
        {
            value %= modulus;
            return value.Sign < 0 ? value + modulus : value;
        }

        private static BigInteger HalveModulo(BigInteger value, BigInteger modulus)
        {
            value = Normalize(value, modulus);
            return (value.IsEven ? value : value + modulus) >> 1;
        }
    }
}
