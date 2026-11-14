using System.Numerics;
using System.Security.Cryptography;

namespace Gearbox.Cryptography
{
    /// <summary>
    /// Generates RSA keys using custom prime searches and derives two-prime RSA parameters.
    /// </summary>
    /// <remarks>
    /// Prefer <see cref="RSA.Create(int)" /> for ordinary key generation; use RSA for import, export,
    /// and cryptographic operations. Custom generation supports cooperative cancellation and uses
    /// Gearbox's <see cref="Prime" /> implementation, with no claimed security or performance advantage.
    /// Dispose generated RSA instances. Generation clears temporary parameter arrays after import;
    /// arrays returned by CreateFullKeyParameters belong to the caller. Immutable BigInteger values
    /// cannot be reliably erased.
    /// </remarks>
    /// <example>
    /// <code>
    /// using RSA key = RSAKey.Generate(2048);
    /// </code>
    /// </example>
    public static class RSAKey
    {
        private const int MinimumGenerationBitLength = 2048;
        private const int MaximumGenerationBitLength = 16384;
        private const int PublicExponent = 65537;

        /// <summary>
        /// Generates an RSA key with exactly the requested modulus bit length and public exponent 65537.
        /// </summary>
        /// <param name="bitLength">
        /// Modulus length from 2048 through 16384 bits, in increments supported by the platform RSA provider.
        /// Unsupported sizes are rejected without rounding.
        /// </param>
        /// <param name="cancellationToken">Cancellation checked between searches and computational steps.</param>
        /// <returns>An initialized RSA key that the caller must dispose.</returns>
        /// <remarks>
        /// P and Q are sampled by separate equal-width probable-prime searches using <see cref="Prime" />.
        /// Each prime search may use all physical cores. Cancellation cannot interrupt individual BigInteger
        /// operations, parameter derivation, or native import. Later KeySize assignments use platform generation.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">The requested size is outside the generation range or unsupported by the provider.</exception>
        /// <exception cref="OperationCanceledException">The caller requested cancellation.</exception>
        /// <example>
        /// <code>
        /// using RSA key = RSAKey.Generate(2048);
        /// byte[] signature = key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        /// </code>
        /// </example>
        public static RSA Generate(int bitLength, CancellationToken cancellationToken = default)
        {
            ValidateGenerationRange(bitLength);
            return Generate(bitLength, Prime.Generate, RSA.Create(), cancellationToken);
        }

        /// <summary>
        /// Asynchronously generates an RSA key with exactly the requested modulus bit length and public exponent 65537.
        /// </summary>
        /// <param name="bitLength">Modulus length from 2048 through 16384 bits, in platform-supported increments.</param>
        /// <param name="cancellationToken">Cancellation checked between searches and computational steps.</param>
        /// <returns>A task containing an initialized RSA key that the caller must dispose.</returns>
        /// <remarks>
        /// Argument validation is synchronous. A valid request with a pre-canceled token returns a canceled task.
        /// P and Q searches are awaited sequentially and complete all their workers before completion.
        /// Cancellation and later KeySize assignments behave as described for <see cref="Generate(int, CancellationToken)" />.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">The requested size is outside the generation range or unsupported by the provider.</exception>
        /// <example>
        /// <code>
        /// using RSA generated =
        ///     await RSAKey.GenerateAsync(2048, cancellationToken);
        /// </code>
        /// </example>
        public static Task<RSA> GenerateAsync(int bitLength, CancellationToken cancellationToken = default)
        {
            ValidateGenerationRange(bitLength);
            return GenerateAsync(bitLength, Prime.GenerateAsync, RSA.Create(), cancellationToken);
        }

        /// <summary>
        /// Derives a complete two-prime RSA private key from the public exponent and primes,
        /// verifying their product against an expected modulus.
        /// </summary>
        /// <param name="exponent">The odd public exponent, greater than one, less than the modulus, and coprime to (p - 1) * (q - 1).</param>
        /// <param name="p">The private odd prime P, greater than two and distinct from Q.</param>
        /// <param name="q">The private odd prime Q, greater than two and distinct from P.</param>
        /// <param name="modulus">The expected product p * q, checked in all build configurations.</param>
        /// <returns>
        /// All eight unsigned big-endian RSA parameter arrays, including the computed modulus.
        /// D has the modulus width; P, Q, DP, DQ, and InverseQ have half that width, rounded up.
        /// </returns>
        /// <remarks>
        /// Uses the three-argument overload for derivation. Primality is the caller's responsibility,
        /// and each prime must fit half the modulus width, rounded up.
        /// The supplied modulus is only used for verification.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">An exponent or prime is outside its allowed range or is even.</exception>
        /// <exception cref="ArgumentException">
        /// The modulus differs from p * q, the primes are equal or too wide, or a required modular inverse does not exist.
        /// </exception>
        public static RSAParameters CreateFullKeyParameters(BigInteger exponent, BigInteger p, BigInteger q, BigInteger modulus)
        {
            if (modulus != p * q)
            {
                throw new ArgumentException("Supplied modulus is incorrect.", nameof(modulus));
            }

            return CreateFullKeyParameters(exponent, p, q);
        }

        /// <summary>
        /// Derives the modulus, private exponent, and CRT parameters of a two-prime RSA key
        /// from its public exponent and private primes.
        /// </summary>
        /// <param name="exponent">The odd public exponent, greater than one, less than the modulus, and coprime to (p - 1) * (q - 1).</param>
        /// <param name="p">The private odd prime P, greater than two and distinct from Q.</param>
        /// <param name="q">The private odd prime Q, greater than two and distinct from P.</param>
        /// <returns>
        /// All eight unsigned big-endian RSA parameter arrays. D has the modulus width;
        /// P, Q, DP, DQ, and InverseQ have half that width, rounded up, with leading-zero padding as needed.
        /// </returns>
        /// <remarks>
        /// Computes n = p * q, d as the inverse of the exponent modulo (p - 1) * (q - 1),
        /// DP = d mod (p - 1), DQ = d mod (q - 1), and InverseQ as the inverse of q modulo p.
        /// Primality is the caller's responsibility; each prime must fit half the modulus width,
        /// rounded up. The returned arrays contain private key material.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">An exponent or prime is outside its allowed range or is even.</exception>
        /// <exception cref="ArgumentException">
        /// The primes are equal or too wide, or a required modular inverse does not exist.
        /// </exception>
        public static RSAParameters CreateFullKeyParameters(BigInteger exponent, BigInteger p, BigInteger q)
        {
            if (exponent <= 1 || exponent.IsEven)
            {
                throw new ArgumentOutOfRangeException(nameof(exponent), "The public exponent must be odd and greater than one.");
            }

            if (p <= 2 || p.IsEven)
            {
                throw new ArgumentOutOfRangeException(nameof(p), "P must be an odd prime greater than two.");
            }

            if (q <= 2 || q.IsEven)
            {
                throw new ArgumentOutOfRangeException(nameof(q), "Q must be an odd prime greater than two.");
            }

            if (p == q)
            {
                throw new ArgumentException("The private primes must be distinct.", nameof(q));
            }

            BigInteger modulus = p * q;
            if (exponent >= modulus)
            {
                throw new ArgumentOutOfRangeException(nameof(exponent), "The public exponent must be less than the modulus.");
            }

            byte[] modulusBytes = GetBigIntegerBytes(modulus);
            int primeLength = (modulusBytes.Length + 1) / 2;
            if (p.GetByteCount(isUnsigned: true) > primeLength)
            {
                throw new ArgumentException("P must fit half the modulus width, rounded up.", nameof(p));
            }

            if (q.GetByteCount(isUnsigned: true) > primeLength)
            {
                throw new ArgumentException("Q must fit half the modulus width, rounded up.", nameof(q));
            }

            BigInteger phiOfN = (p - 1) * (q - 1);
            BigInteger d = ModInverse(exponent, phiOfN, nameof(exponent));
            BigInteger dp = d % (p - 1);
            BigInteger dq = d % (q - 1);
            BigInteger qInv = ModInverse(q, p, nameof(q));

            return new RSAParameters
            {
                Exponent = GetBigIntegerBytes(exponent),
                Modulus = modulusBytes,
                P = GetBigIntegerBytes(p, primeLength),
                Q = GetBigIntegerBytes(q, primeLength),
                D = GetBigIntegerBytes(d, modulusBytes.Length),
                DP = GetBigIntegerBytes(dp, primeLength),
                DQ = GetBigIntegerBytes(dq, primeLength),
                InverseQ = GetBigIntegerBytes(qInv, primeLength)
            };
        }

        // Operation-local seams. Delegates must return exact-bit-length probable primes.
        // The factory owns the supplied provider, including when validation or generation fails.
        internal static RSA Generate(int bitLength, Func<int, CancellationToken, BigInteger> generatePrime,
            RSA provider, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(provider);
            try
            {
                ArgumentNullException.ThrowIfNull(generatePrime);
                ValidateGenerationSize(bitLength, provider.LegalKeySizes);
                cancellationToken.ThrowIfCancellationRequested();

                int primeBits = bitLength / 2;
                BigInteger minimumSeparation = BigInteger.One << (primeBits - 100);
                while (true)
                {
                    BigInteger p;
                    do
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        p = generatePrime(primeBits, cancellationToken);
                        cancellationToken.ThrowIfCancellationRequested();
                    } while (!IsExponentCompatible(p));

                    BigInteger q;
                    do
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        q = generatePrime(primeBits, cancellationToken);
                        cancellationToken.ThrowIfCancellationRequested();
                    } while (!IsAcceptableQ(p, q, minimumSeparation));

                    if ((p * q).GetBitLength() == bitLength)
                    {
                        return ImportGeneratedKey(provider, p, q, cancellationToken);
                    }

                    // Restart both primes rather than retaining a P that rarely produces a full-width modulus.
                }
            }
            catch
            {
                provider.Dispose();
                throw;
            }
        }

        internal static Task<RSA> GenerateAsync(int bitLength, Func<int, CancellationToken, Task<BigInteger>> generatePrime,
            RSA provider, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(provider);
            try
            {
                ArgumentNullException.ThrowIfNull(generatePrime);
                ValidateGenerationSize(bitLength, provider.LegalKeySizes);
                if (cancellationToken.IsCancellationRequested)
                {
                    provider.Dispose();
                    return Task.FromCanceled<RSA>(cancellationToken);
                }

                return GenerateCoreAsync(provider, bitLength, generatePrime, cancellationToken);
            }
            catch
            {
                provider.Dispose();
                throw;
            }
        }

        private static async Task<RSA> GenerateCoreAsync(RSA provider, int bitLength,
            Func<int, CancellationToken, Task<BigInteger>> generatePrime, CancellationToken cancellationToken)
        {
            try
            {
                int primeBits = bitLength / 2;
                BigInteger minimumSeparation = BigInteger.One << (primeBits - 100);
                while (true)
                {
                    BigInteger p;
                    do
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        p = await generatePrime(primeBits, cancellationToken).ConfigureAwait(false);
                        cancellationToken.ThrowIfCancellationRequested();
                    } while (!IsExponentCompatible(p));

                    BigInteger q;
                    do
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        q = await generatePrime(primeBits, cancellationToken).ConfigureAwait(false);
                        cancellationToken.ThrowIfCancellationRequested();
                    } while (!IsAcceptableQ(p, q, minimumSeparation));

                    if ((p * q).GetBitLength() == bitLength)
                    {
                        return ImportGeneratedKey(provider, p, q, cancellationToken);
                    }
                }
            }
            catch
            {
                provider.Dispose();
                throw;
            }
        }

        private static bool IsExponentCompatible(BigInteger prime) =>
            BigInteger.GreatestCommonDivisor(PublicExponent, prime - 1) == BigInteger.One;

        private static bool IsAcceptableQ(BigInteger p, BigInteger q, BigInteger minimumSeparation) =>
            IsExponentCompatible(q) && p != q && BigInteger.Abs(p - q) > minimumSeparation;

        private static RSA ImportGeneratedKey(RSA provider, BigInteger p, BigInteger q, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RSAParameters parameters = RSAKey.CreateFullKeyParameters(PublicExponent, p, q);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                provider.ImportParameters(parameters);
                cancellationToken.ThrowIfCancellationRequested();
                return provider;
            }
            finally
            {
                ClearGeneratedParameters(parameters);
            }
        }

        private static void ClearGeneratedParameters(RSAParameters parameters)
        {
            CryptographicOperations.ZeroMemory(parameters.Modulus);
            CryptographicOperations.ZeroMemory(parameters.Exponent);
            CryptographicOperations.ZeroMemory(parameters.D);
            CryptographicOperations.ZeroMemory(parameters.P);
            CryptographicOperations.ZeroMemory(parameters.Q);
            CryptographicOperations.ZeroMemory(parameters.DP);
            CryptographicOperations.ZeroMemory(parameters.DQ);
            CryptographicOperations.ZeroMemory(parameters.InverseQ);
        }

        private static void ValidateGenerationRange(int bitLength)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(bitLength, MinimumGenerationBitLength);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(bitLength, MaximumGenerationBitLength);
        }

        private static void ValidateGenerationSize(int bitLength, KeySizes[] legalKeySizes)
        {
            ValidateGenerationRange(bitLength);
            foreach (KeySizes size in legalKeySizes)
            {
                if (size.SkipSize == 0 ? bitLength == size.MinSize :
                    bitLength >= size.MinSize && bitLength <= size.MaxSize && (bitLength - size.MinSize) % size.SkipSize == 0)
                {
                    return;
                }
            }

            throw new ArgumentOutOfRangeException(nameof(bitLength), "The requested size is unsupported by the platform RSA provider.");
        }

        /// <summary>
        /// Converts a non-negative integer to an unsigned big-endian byte array, optionally padded on the left.
        /// </summary>
        /// <param name="bi">The non-negative integer to convert.</param>
        /// <param name="minimumLength">The minimum array length, or zero for a minimally sized magnitude.</param>
        /// <returns>A new array containing the magnitude with leading-zero padding as needed; zero uses at least one byte.</returns>
        /// <exception cref="OverflowException">The integer is negative.</exception>
        private static byte[] GetBigIntegerBytes(BigInteger bi, int minimumLength = 0)
        {
            int valueLength = bi.GetByteCount(isUnsigned: true);
            byte[] bytes = new byte[Math.Max(valueLength, minimumLength)];
            bi.TryWriteBytes(bytes.AsSpan(bytes.Length - valueLength), out _, isUnsigned: true, isBigEndian: true);
            return bytes;
        }

        /// <summary>
        /// Calculates the modular multiplicative inverse of a modulo n using the extended Euclidean algorithm.
        /// </summary>
        /// <param name="a">The positive integer whose inverse is required.</param>
        /// <param name="n">The modulus, greater than one.</param>
        /// <param name="parameterName">The public argument name to report if no inverse exists.</param>
        /// <returns>The value t in [0, n) for which (a * t) mod n equals one.</returns>
        /// <remarks>Callers must supply positive operands; this helper does not validate their ranges.</remarks>
        /// <exception cref="ArgumentException">The operands are not coprime.</exception>
        private static BigInteger ModInverse(BigInteger a, BigInteger n, string parameterName)
        {
            BigInteger t = 0;
            BigInteger nt = 1;
            BigInteger r = n;
            BigInteger nr = a;

            while (nr != 0)
            {
                BigInteger quot = r / nr;
                BigInteger tmp = nt;
                nt = t - quot * nt;
                t = tmp;
                tmp = nr;
                nr = r - quot * nr;
                r = tmp;
            }

            if (r != 1)
            {
                throw new ArgumentException("Integer is not invertible.", parameterName);
            }

            if (t < 0)
            {
                t += n;
            }

            return t;
        }
    }
}
