using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;

namespace Gearbox.Cryptography
{
    /// <summary>
    /// Derives two-prime RSA private key parameters and serializes them as PKCS #1 PEM.
    /// </summary>
    public static class RSAKey
    {
        /// <summary>
        /// Serializes a complete two-prime RSA private key as DER in an unencrypted PKCS #1 PEM envelope.
        /// </summary>
        /// <param name="rsaParameters">
        /// The private key parameters. All eight arrays must be non-null, non-empty,
        /// unsigned big-endian values; leading-zero padding is accepted.
        /// </param>
        /// <returns>
        /// A string with RSA PRIVATE KEY delimiters and Base64 content wrapped at 76 characters,
        /// without a newline after the closing delimiter.
        /// </returns>
        /// <remarks>
        /// Encodes a version-zero RSAPrivateKey sequence, removing redundant leading zeros from each
        /// INTEGER. This method does not verify the mathematical consistency of the key.
        /// The input arrays are not modified or cleared. The writer's temporary DER data is cleared,
        /// but the returned string contains private key material and cannot be reliably cleared.
        /// </remarks>
        /// <exception cref="ArgumentException">A required parameter array is null or empty.</exception>
        public static string EncodeParametersPem(RSAParameters rsaParameters)
        {
            ReadOnlySpan<byte> modulus = GetUnsignedParameterBytes(rsaParameters.Modulus, nameof(RSAParameters.Modulus));
            ReadOnlySpan<byte> exponent = GetUnsignedParameterBytes(rsaParameters.Exponent, nameof(RSAParameters.Exponent));
            ReadOnlySpan<byte> d = GetUnsignedParameterBytes(rsaParameters.D, nameof(RSAParameters.D));
            ReadOnlySpan<byte> p = GetUnsignedParameterBytes(rsaParameters.P, nameof(RSAParameters.P));
            ReadOnlySpan<byte> q = GetUnsignedParameterBytes(rsaParameters.Q, nameof(RSAParameters.Q));
            ReadOnlySpan<byte> dp = GetUnsignedParameterBytes(rsaParameters.DP, nameof(RSAParameters.DP));
            ReadOnlySpan<byte> dq = GetUnsignedParameterBytes(rsaParameters.DQ, nameof(RSAParameters.DQ));
            ReadOnlySpan<byte> inverseQ = GetUnsignedParameterBytes(rsaParameters.InverseQ, nameof(RSAParameters.InverseQ));

            // Each INTEGER needs at most seven overhead bytes (tag, length, sign byte),
            // plus six for the SEQUENCE header and three for the version INTEGER.
            int capacity = checked(modulus.Length + exponent.Length + d.Length + p.Length + q.Length +
                dp.Length + dq.Length + inverseQ.Length + 8 * 7 + 6 + 3);
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER, capacity);
            try
            {
                writer.PushSequence();
                writer.WriteInteger(0);
                writer.WriteIntegerUnsigned(modulus);
                writer.WriteIntegerUnsigned(exponent);
                writer.WriteIntegerUnsigned(d);
                writer.WriteIntegerUnsigned(p);
                writer.WriteIntegerUnsigned(q);
                writer.WriteIntegerUnsigned(dp);
                writer.WriteIntegerUnsigned(dq);
                writer.WriteIntegerUnsigned(inverseQ);
                writer.PopSequence();

                return writer.Encode(static encoded => string.Concat(
                    Certificate.PemRsaKeyHeader, Environment.NewLine,
                    Convert.ToBase64String(encoded, Base64FormattingOptions.InsertLineBreaks),
                    Environment.NewLine, Certificate.PemRsaKeyFooter));
            }
            finally
            {
                writer.Reset();
            }
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

        /// <summary>
        /// Validates an RSA parameter array and exposes its minimally sized unsigned magnitude without copying it.
        /// </summary>
        /// <param name="value">The non-null, non-empty unsigned big-endian parameter bytes.</param>
        /// <param name="fieldName">The RSAParameters field name to report if the array is missing or empty.</param>
        /// <returns>A span over the original array without leading zeros, retaining one zero byte for the value zero.</returns>
        /// <exception cref="ArgumentException">The array is null or empty.</exception>
        private static ReadOnlySpan<byte> GetUnsignedParameterBytes(byte[]? value, string fieldName)
        {
            if (value == null || value.Length == 0)
            {
                throw new ArgumentException("The RSA parameter must be non-null and non-empty.", fieldName);
            }

            int offset = 0;
            while (offset < value.Length - 1 && value[offset] == 0)
            {
                offset++;
            }

            return value.AsSpan(offset);
        }
    }
}
