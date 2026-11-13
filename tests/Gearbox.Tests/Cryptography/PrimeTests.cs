using System.Numerics;
using Gearbox.Cryptography;

namespace Gearbox.Tests.Cryptography
{
    [TestClass]
    public class PrimeTests
    {
        [TestMethod]
        [DataRow(int.MinValue)]
        [DataRow(-1)]
        [DataRow(0)]
        [DataRow(1)]
        public void Generate_InvalidBitLength_ThrowsBeforeScheduling(int bitLength)
        {
            ArgumentOutOfRangeException sync = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Prime.Generate(bitLength));
            ArgumentOutOfRangeException async = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Prime.GenerateAsync(bitLength));

            Assert.AreEqual("bitLength", sync.ParamName);
            Assert.AreEqual("bitLength", async.ParamName);
        }

        [TestMethod]
        [DataRow(2, "00", 2)]
        [DataRow(2, "FD", 3)]
        [DataRow(3, "FC", 5)]
        [DataRow(7, "3E", 127)]
        [DataRow(8, "7A", 251)]
        [DataRow(9, "FEFC", 509)]
        [DataRow(10, "01F0", 1009)]
        [DataRow(13, "AFFE", 8191)]
        [DataRow(16, "7FF0", 65521)]
        [DataRow(17, "FEFFFE", 131071)]
        public void Generate_ShapesRandomBytes_ReturnsExpectedPrime(int bitLength, string rawHex, int expected)
        {
            byte[] raw = Convert.FromHexString(rawHex);
            int expectedDraws = expected > 997 ? 65 : 1;
            int draws = 0;
            BigInteger result = Prime.Generate(bitLength, bytes =>
            {
                Assert.IsTrue(++draws <= expectedDraws, "Unexpected extra random draw.");
                if (draws == 1)
                {
                    Assert.AreEqual(raw.Length, bytes.Length);
                    raw.CopyTo(bytes);
                }
                else
                {
                    bytes.Clear();
                }
            }, CancellationToken.None);

            Assert.AreEqual(new BigInteger(expected), result);
            Assert.AreEqual((long)bitLength, result.GetBitLength());
            Assert.AreEqual(expectedDraws, draws);
        }

        [TestMethod]
        public void Generate_TwoBits_SamplesBothPrimesEqually()
        {
            int twos = 0;
            int threes = 0;
            for (int raw = 0; raw <= byte.MaxValue; raw++)
            {
                int draws = 0;
                BigInteger result = Prime.Generate(2, bytes =>
                {
                    Assert.AreEqual(1, ++draws);
                    Assert.AreEqual(1, bytes.Length);
                    bytes[0] = (byte)raw;
                }, CancellationToken.None);
                Assert.IsTrue(result == 2 || result == 3);
                if (result == 2)
                {
                    twos++;
                }
                else
                {
                    threes++;
                }
            }

            Assert.AreEqual(128, twos);
            Assert.AreEqual(128, threes);
        }

        [TestMethod]
        public void Generate_RejectedCandidate_DrawsFreshBytes()
        {
            int draws = 0;
            BigInteger result = Prime.Generate(13, bytes =>
            {
                Assert.IsTrue(++draws <= 66, "Unexpected extra random draw.");
                bytes.Clear();
                // The first all-zero draw becomes 4097 = 17 * 241.
                // The next candidate becomes 8191 after masking and setting its bits.
                if (draws == 2)
                {
                    bytes[0] = 0xAF;
                    bytes[1] = 0xFE;
                }
            }, CancellationToken.None);

            Assert.AreEqual(new BigInteger(8191), result);
            Assert.AreEqual(66, draws);
        }

        [TestMethod]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(7)]
        [DataRow(8)]
        [DataRow(9)]
        [DataRow(13)]
        [DataRow(16)]
        [DataRow(17)]
        [DataRow(64)]
        [DataRow(65)]
        [DataRow(128)]
        [DataRow(256)]
        [DataRow(512)]
        [DataRow(1024)]
        [DataRow(2048)]
        [DoNotParallelize]
        public void Generate_RealRandomSource_ReturnsExactBitLengthPrime(int bitLength)
        {
            BigInteger result = Prime.Generate(bitLength);

            Assert.AreEqual((long)bitLength, result.GetBitLength());
            Assert.IsTrue(result.Sign > 0);
            Assert.IsTrue(result == 2 || !result.IsEven);
            Assert.IsTrue(Prime.IsProbablePrime(result));
            if (bitLength <= 17)
            {
                Assert.IsTrue(IsPrimeByTrialDivision((int)result));
            }
        }

        [TestMethod]
        [DataRow(2)]
        [DataRow(13)]
        [DataRow(65)]
        [DataRow(256)]
        public async Task GenerateAsync_ReturnsExactBitLengthPrime(int bitLength)
        {
            BigInteger result = await Prime.GenerateAsync(bitLength);

            Assert.AreEqual((long)bitLength, result.GetBitLength());
            Assert.IsTrue(await Prime.IsProbablePrimeAsync(result));
        }

        [TestMethod]
        public void IsProbablePrime_ThroughTenThousand_MatchesIndependentSieve()
        {
            bool[] primes = BuildSieve(10000);
            for (int candidate = 0; candidate < primes.Length; candidate++)
            {
                Assert.AreEqual(primes[candidate], Prime.IsProbablePrime(candidate, FillZero, CancellationToken.None), $"Candidate {candidate}.");
            }
        }

        [TestMethod]
        [DataRow(-100)]
        [DataRow(-1)]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(4)]
        [DataRow(561)]
        [DataRow(1105)]
        [DataRow(1729)]
        [DataRow(2465)]
        [DataRow(2821)]
        [DataRow(6601)]
        [DataRow(25326001)]
        [DataRow(1018081)]
        public void IsProbablePrime_CompositesAndNonPrimes_RejectWithoutRandomRounds(int candidate)
        {
            Assert.IsFalse(Prime.IsProbablePrime(candidate, FailIfRandomRequested, CancellationToken.None));
        }

        [TestMethod]
        [DataRow(127)]
        [DataRow(521)]
        public void IsProbablePrime_KnownMersennePrime_Accepts(int exponent)
        {
            BigInteger candidate = (BigInteger.One << exponent) - 1;

            Assert.IsTrue(Prime.IsMillerRabinProbablePrime(candidate, 2));
            Assert.IsTrue(Prime.IsStrongLucasProbablePrime(candidate));
            Assert.IsTrue(Prime.IsProbablePrime(candidate));
        }

        [TestMethod]
        public void IsProbablePrime_LargeProductsAndSquares_Rejects()
        {
            BigInteger p = (BigInteger.One << 127) - 1;
            BigInteger q = (BigInteger.One << 61) - 1;

            Assert.IsFalse(Prime.IsProbablePrime(p * q, FailIfRandomRequested, CancellationToken.None));
            Assert.IsFalse(Prime.IsProbablePrime(p * p, FailIfRandomRequested, CancellationToken.None));
            Assert.IsFalse(Prime.IsStrongLucasProbablePrime(p * p));
            Assert.IsFalse(Prime.IsProbablePrime(-p));
        }

        [TestMethod]
        [DataRow(-1, false)]
        [DataRow(0, false)]
        [DataRow(1, false)]
        [DataRow(2, true)]
        [DataRow(3, true)]
        [DataRow(4, false)]
        [DataRow(997, true)]
        [DataRow(1009, true)]
        [DataRow(25326001, false)]
        public async Task IsProbablePrimeAsync_MatchesExpectedResult(int candidate, bool expected)
        {
            Assert.AreEqual(expected, await Prime.IsProbablePrimeAsync(candidate));
        }

        [TestMethod]
        [DataRow(2047L, 2, true)]
        [DataRow(2047L, 3, false)]
        [DataRow(1373653L, 2, true)]
        [DataRow(1373653L, 3, true)]
        [DataRow(1373653L, 5, false)]
        [DataRow(3215031751L, 7, true)]
        [DataRow(3215031751L, 11, false)]
        [DataRow(561L, 2, false)]
        public void MillerRabin_KnownWitnesses_MatchesExpectedResult(long candidate, int witness, bool expected)
        {
            Assert.AreEqual(expected, Prime.IsMillerRabinProbablePrime(candidate, witness));
        }

        [TestMethod]
        public void StrongLucas_ThroughTenThousand_MatchesPrimesAndKnownPseudoprimes()
        {
            bool[] primes = BuildSieve(10000);
            // Independently checked with SymPy's strong Lucas-Selfridge implementation.
            for (int candidate = 3; candidate < primes.Length; candidate += 2)
            {
                bool expected = primes[candidate] || candidate == 5459 || candidate == 5777;
                Assert.AreEqual(expected, Prime.IsStrongLucasProbablePrime(candidate), $"Candidate {candidate}.");
            }
        }

        [TestMethod]
        [DataRow(5, true)]
        [DataRow(15, false)]
        [DataRow(25, false)]
        [DataRow(2047, false)]
        [DataRow(5459, true)]
        [DataRow(10877, true)]
        [DataRow(16109, true)]
        [DataRow(25326001, false)]
        [DataRow(1018081, false)]
        public void StrongLucas_FactorsSquaresAndPseudoprimes_MatchesExpectedResult(int candidate, bool expected)
        {
            Assert.AreEqual(expected, Prime.IsStrongLucasProbablePrime(candidate));
        }

        [TestMethod]
        [DataRow(5, 7, -1)]
        [DataRow(5, 11, 1)]
        [DataRow(-7, 11, 1)]
        [DataRow(-7, 13, -1)]
        [DataRow(2, 3, -1)]
        [DataRow(2, 5, -1)]
        [DataRow(2, 7, 1)]
        [DataRow(2, 9, 1)]
        [DataRow(3, 9, 0)]
        [DataRow(0, 7, 0)]
        [DataRow(123, 1, 1)]
        public void JacobiSymbol_NegativeEvenAndNonCoprimeInputs_MatchesExpectedResult(int value, int modulus, int expected)
        {
            Assert.AreEqual(expected, Prime.JacobiSymbol(value, modulus));
        }

        [TestMethod]
        public void IsProbablePrime_AcceptedCandidate_UsesSixtyFourAdditionalRandomRounds()
        {
            int draws = 0;
            Assert.IsTrue(Prime.IsProbablePrime(1009, bytes =>
            {
                Assert.IsTrue(++draws <= 64);
                bytes.Clear();
            }, CancellationToken.None));

            Assert.AreEqual(64, draws);
        }

        [TestMethod]
        public void SampleBelow_ZeroBytes_DoesNotForceHighestBit()
        {
            BigInteger result = Prime.SampleBelow(1006, new byte[2], 0x03, FillZero, CancellationToken.None);

            Assert.AreEqual(BigInteger.Zero, result);
        }

        [TestMethod]
        public void SampleBelow_ExclusiveBound_RejectsAndAcceptsMaximumOffset()
        {
            int draws = 0;
            BigInteger result = Prime.SampleBelow(1006, new byte[2], 0x03, bytes =>
            {
                Assert.IsTrue(++draws <= 2);
                bytes[0] = 0xFF;
                bytes[1] = draws == 1 ? (byte)0xEE : (byte)0xED;
            }, CancellationToken.None);

            Assert.AreEqual(new BigInteger(1005), result);
            Assert.AreEqual(2, draws);
        }

        [TestMethod]
        public void IsProbablePrime_WitnessSampling_MasksRejectsAndAcceptsBothEndpoints()
        {
            int draws = 0;
            Assert.IsTrue(Prime.IsProbablePrime(1009, bytes =>
            {
                Assert.IsTrue(draws < 96, "Unexpected extra random draw.");
                Assert.AreEqual(2, bytes.Length);
                int step = draws++ % 3;
                bytes.Clear();
                if (step != 1)
                {
                    bytes[0] = 0xFF;
                    // After masking: 1006 is rejected; 1005 gives witness 1007.
                    bytes[1] = step == 0 ? (byte)0xEE : (byte)0xED;
                }
                // All-zero bytes give witness 2, the other inclusive endpoint.
            }, CancellationToken.None));

            Assert.AreEqual(96, draws);
        }

        [TestMethod]
        [DataRow(2)]
        [DataRow(int.MaxValue)]
        public void Generate_PreCanceledToken_ThrowsBeforeAllocation(int bitLength)
        {
            CancellationToken token = new CancellationToken(true);
            OperationCanceledException exception = Assert.ThrowsExactly<OperationCanceledException>(() => Prime.Generate(bitLength, token));

            Assert.AreEqual(token, exception.CancellationToken);
        }

        [TestMethod]
        [DataRow(-1)]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(4)]
        [DataRow(1009)]
        public void IsProbablePrime_PreCanceledToken_ThrowsBeforeFastReturns(int candidate)
        {
            CancellationToken token = new CancellationToken(true);
            OperationCanceledException exception = Assert.ThrowsExactly<OperationCanceledException>(() => Prime.IsProbablePrime(candidate, token));

            Assert.AreEqual(token, exception.CancellationToken);
        }

        [TestMethod]
        public async Task AsyncMethods_PreCanceledToken_ReturnCanceledTasks()
        {
            CancellationToken token = new CancellationToken(true);
            Task<BigInteger> generation = Prime.GenerateAsync(int.MaxValue, token);
            Task<bool> checking = Prime.IsProbablePrimeAsync(2, token);
            OperationCanceledException generateException = await Assert.ThrowsAsync<OperationCanceledException>(() => generation);
            OperationCanceledException checkException = await Assert.ThrowsAsync<OperationCanceledException>(() => checking);

            Assert.AreEqual(token, generateException.CancellationToken);
            Assert.AreEqual(token, checkException.CancellationToken);
            Assert.IsTrue(generation.IsCanceled);
            Assert.IsTrue(checking.IsCanceled);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Generate_CancelDuringCandidateResampling_PropagatesCancellation(bool asynchronous)
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            int draws = 0;
            Prime.RandomByteFiller source = bytes =>
            {
                bytes.Clear();
                if (++draws == 2)
                {
                    cancellation.Cancel();
                }
            };
            OperationCanceledException exception;
            if (asynchronous)
            {
                Task<BigInteger> task = Prime.GenerateAsync(13, source, cancellation.Token);
                exception = await Assert.ThrowsAsync<OperationCanceledException>(() => task);
                Assert.IsTrue(task.IsCanceled);
            }
            else
            {
                exception = Assert.ThrowsExactly<OperationCanceledException>(() => Prime.Generate(13, source, cancellation.Token));
            }

            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.AreEqual(2, draws);
        }

        [TestMethod]
        [DataRow(false, 1)]
        [DataRow(false, 64)]
        [DataRow(true, 1)]
        [DataRow(true, 64)]
        public async Task IsProbablePrime_CancelDuringRandomRounds_PropagatesCancellation(bool asynchronous, int cancelAtDraw)
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            int draws = 0;
            Prime.RandomByteFiller source = bytes =>
            {
                bytes.Clear();
                if (++draws == cancelAtDraw)
                {
                    cancellation.Cancel();
                }
            };
            OperationCanceledException exception;
            if (asynchronous)
            {
                Task<bool> task = Prime.IsProbablePrimeAsync(1009, source, cancellation.Token);
                exception = await Assert.ThrowsAsync<OperationCanceledException>(() => task);
                Assert.IsTrue(task.IsCanceled);
            }
            else
            {
                exception = Assert.ThrowsExactly<OperationCanceledException>(() => Prime.IsProbablePrime(1009, source, cancellation.Token));
            }

            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.AreEqual(cancelAtDraw, draws);
        }

        [TestMethod]
        public void IsProbablePrime_CancelDuringWitnessRejection_PropagatesCancellation()
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            int draws = 0;
            OperationCanceledException exception = Assert.ThrowsExactly<OperationCanceledException>(() => Prime.IsProbablePrime(1009, bytes =>
            {
                bytes.Fill(byte.MaxValue);
                if (++draws == 3)
                {
                    cancellation.Cancel();
                }
            }, cancellation.Token));

            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.AreEqual(3, draws);
        }

        [TestMethod]
        public void MathematicalComponents_PreCanceledToken_PropagateCancellation()
        {
            CancellationToken token = new CancellationToken(true);

            Assert.ThrowsExactly<OperationCanceledException>(() => Prime.IsMillerRabinProbablePrime(1009, 2, token));
            Assert.ThrowsExactly<OperationCanceledException>(() => Prime.IsStrongLucasProbablePrime(1009, token));
            Assert.ThrowsExactly<OperationCanceledException>(() => Prime.JacobiSymbol(5, 1009, token));
        }

        private static void FillZero(Span<byte> bytes) => bytes.Clear();

        private static void FailIfRandomRequested(Span<byte> bytes) => Assert.Fail("Preliminary checks should have rejected the candidate.");

        private static bool[] BuildSieve(int limit)
        {
            bool[] primes = new bool[limit + 1];
            Array.Fill(primes, true, 2, limit - 1);
            for (int divisor = 2; divisor * divisor <= limit; divisor++)
            {
                if (!primes[divisor])
                {
                    continue;
                }
                for (int multiple = divisor * divisor; multiple <= limit; multiple += divisor)
                {
                    primes[multiple] = false;
                }
            }
            return primes;
        }

        private static bool IsPrimeByTrialDivision(int candidate)
        {
            if (candidate < 2)
            {
                return false;
            }
            for (int divisor = 2; divisor * divisor <= candidate; divisor++)
            {
                if (candidate % divisor == 0)
                {
                    return false;
                }
            }
            return true;
        }
    }
}
