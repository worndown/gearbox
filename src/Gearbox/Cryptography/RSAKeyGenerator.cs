using System.Numerics;
using System.Security.Cryptography;

namespace Gearbox.Cryptography
{
    /// <summary>
    /// Generates RSA keys with Gearbox's custom prime searches and imports them into a platform RSA provider.
    /// </summary>
    /// <remarks>
    /// Prefer RSA.Create(bitLength) for ordinary key generation. Custom generation supports cooperative
    /// cancellation and deliberate algorithm control; it offers no claimed security or performance advantage.
    /// The caller owns the returned provider and must dispose it. Temporary parameter arrays are cleared
    /// after import; immutable BigInteger values cannot be reliably erased.
    /// </remarks>
    public static class RSAKeyGenerator
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
        /// using RSA key = RSAKeyGenerator.Generate(2048);
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
        ///     await RSAKeyGenerator.GenerateAsync(2048, cancellationToken);
        /// </code>
        /// </example>
        public static Task<RSA> GenerateAsync(int bitLength, CancellationToken cancellationToken = default)
        {
            ValidateGenerationRange(bitLength);
            return GenerateAsync(bitLength, Prime.GenerateAsync, RSA.Create(), cancellationToken);
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
    }
}
