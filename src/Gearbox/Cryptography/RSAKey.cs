using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Gearbox.Cryptography
{
    /// <summary>
    /// RSA key helper.
    /// </summary>
    public static class RSAKey
    {
        /// <summary>
        /// Encodes RSA private key parameters in PEM format.
        /// </summary>
        /// <param name="rsaParameters">The private key parameters.</param>
        /// <returns>String containing private key in PEM format.</returns>
        public static string EncodeParametersPem(RSAParameters rsaParameters)
        {
            byte[] sequence = EncodeRsaPrivateKey(rsaParameters);
            try
            {
                StringBuilder builder = new StringBuilder(512);
                builder.AppendLine(Certificate.PemRsaKeyHeader);
                builder.AppendLine(Convert.ToBase64String(sequence, Base64FormattingOptions.InsertLineBreaks));
                builder.Append(Certificate.PemRsaKeyFooter);
                return builder.ToString();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sequence);
            }
        }

        /// <summary>
        /// Creates full RSA parameter set by deriving from P, Q and exponent
        /// remaining private parameters: d, dp, dq and inverseQ.
        /// </summary>
        /// <param name="exponent">Public exponent.</param>
        /// <param name="p">Private P (prime 1).</param>
        /// <param name="q">Private Q (prime 2).</param>
        /// <param name="modulus">Public modulus (used for verification).</param>
        /// <returns>Full RSA private key.</returns>
        public static RSAParameters CreateFullKeyParameters(BigInteger exponent, BigInteger p, BigInteger q, BigInteger modulus)
        {
            RSAParameters rsaParameters = CreateFullKeyParameters(exponent, p, q);
#if DEBUG
            byte[] modulusBytes = GetBigIntegerBytes(modulus);
            if (!modulusBytes.SequenceEqual(rsaParameters.Modulus))
            {
                throw new ArgumentException("Supplied modulus is incorrect.", nameof(modulus));
            }
#endif
            return rsaParameters;
        }

        /// <summary>
        /// Creates full RSA parameter set by deriving from P, Q and exponent remaining
        /// public (modulus) and private (d, dp, dq and inverseQ) parameters.
        /// </summary>
        /// <param name="exponent">Public exponent.</param>
        /// <param name="p">Private P (prime 1).</param>
        /// <param name="q">Private Q (prime 2).</param>
        /// <returns>Full RSA private key.</returns>
        public static RSAParameters CreateFullKeyParameters(BigInteger exponent, BigInteger p, BigInteger q)
        {
            // Relation between different RSA key parameters outlined here:
            // "https://en.wikipedia.org/wiki/RSA_(cryptosystem)"
            BigInteger modulus = p * q;
            BigInteger phiOfN = (p - 1) * (q - 1);
            BigInteger d = ModInverse(exponent, phiOfN);
            if ((d * exponent) % phiOfN != 1)
            {
                throw new ArgumentException("Invalid value.", nameof(exponent));
            }

            BigInteger dp = d % (p - 1);
            BigInteger dq = d % (q - 1);
            BigInteger qInv = ModInverse(q, p);

            return new RSAParameters
            {
                Exponent = GetBigIntegerBytes(exponent),
                Modulus = GetBigIntegerBytes(modulus),
                P = GetBigIntegerBytes(p),
                Q = GetBigIntegerBytes(q),
                D = GetBigIntegerBytes(d),
                DP = GetBigIntegerBytes(dp),
                DQ = GetBigIntegerBytes(dq),
                InverseQ = GetBigIntegerBytes(qInv)
            };
        }

        /// <summary>
        /// Returns big integer byte value.
        /// </summary>
        /// <param name="bi">BigInteger instance.</param>
        /// <returns>Big integer bytes.</returns>
        private static byte[] GetBigIntegerBytes(BigInteger bi)
        {
            return bi.ToByteArray(isUnsigned: true, isBigEndian: true);
        }

        /// <summary>
        /// Calculates the modular multiplicative inverse of a modulo n using the extended Euclidean algorithm.
        /// See https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers more information.
        /// </summary>
        /// <param name="a">The integer a.</param>
        /// <param name="n">The integer n.</param>
        /// <returns>The modular multiplicative inverse of a modulo n.</returns>
        private static BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            BigInteger t = 0;
            BigInteger nt = 1;
            BigInteger r = n;
            BigInteger nr = a;

            if (n < 0)
            {
                n = -n;
            }

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

            if (r > 1)
            {
                throw new ArgumentException("Integer is not invertible.", nameof(a));
            }

            if (t < 0)
            {
                t += n;
            }

            return t;
        }

        #region ASN.1 key encoding

        /// <summary>
        /// Encodes RSA private key using ASN.1.
        /// </summary>
        /// <param name="rsa">RSA private key.</param>
        /// <returns>ASN.1 encoded sequence.</returns>
        private static byte[] EncodeRsaPrivateKey(RSAParameters rsa)
        {
            // ASN.1 sequence for RSA private key looks like this:
            //
            // RSAPrivateKey ::= SEQUENCE {
            //     version           Version,
            //     modulus           INTEGER,  -- n
            //     publicExponent    INTEGER,  -- e
            //     privateExponent   INTEGER,  -- d
            //     prime1            INTEGER,  -- p
            //     prime2            INTEGER,  -- q
            //     exponent1         INTEGER,  -- d mod (p-1)           <-- RSAParameters.DP
            //     exponent2         INTEGER,  -- d mod (q-1)           <-- RSAParameters.DQ
            //     coefficient       INTEGER,  -- (inverse of q) mod p  <-- RSAParameters.InverseQ
            //     otherPrimeInfos   OtherPrimeInfos OPTIONAL
            // }
            int approxSequenceLen =
                (rsa.D?.Length ?? throw new ArgumentException("Missing private exponent.")) +
                (rsa.DP?.Length ?? throw new ArgumentException("Missing exponent 1.")) +
                (rsa.DQ?.Length ?? throw new ArgumentException("Missing exponent 2.")) +
                (rsa.Exponent?.Length ?? throw new ArgumentException("Missing public exponent.")) +
                (rsa.InverseQ?.Length ?? throw new ArgumentException("Missing inverse Q.")) +
                (rsa.Modulus?.Length ?? throw new ArgumentException("Missing modulus.")) +
                (rsa.P?.Length ?? throw new ArgumentException("Missing prime P.")) +
                (rsa.Q?.Length ?? throw new ArgumentException("Missing prime Q.")) +
                18;

            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(ms))
            {
                try
                {
                    writer.Write((byte)0x30); // Sequence start
                    EncodeIntegerSize(writer, approxSequenceLen); // Sequence length
                    EncodeIntegerValue(writer, [0]); // Version
                    EncodeIntegerValue(writer, rsa.Modulus);
                    EncodeIntegerValue(writer, rsa.Exponent);
                    EncodeIntegerValue(writer, rsa.D);
                    EncodeIntegerValue(writer, rsa.P);
                    EncodeIntegerValue(writer, rsa.Q);
                    EncodeIntegerValue(writer, rsa.DP);
                    EncodeIntegerValue(writer, rsa.DQ);
                    EncodeIntegerValue(writer, rsa.InverseQ);

                    byte[] buffer = ms.ToArray();

                    // Correct the initial sequence length after padding is known.
                    UpdateSequenceSize(buffer);
                    return buffer;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ms.GetBuffer());
                }
            }
        }

        /// <summary>
        /// Encodes integer value.
        /// </summary>
        /// <param name="writer">The output.</param>
        /// <param name="value">Value to encode.</param>
        private static void EncodeIntegerValue(BinaryWriter writer, byte[] value)
        {
            writer.Write((byte)0x02);
            bool align = (value[0] & 0x80) != 0;

            EncodeIntegerSize(writer, align ? value.Length + 1 : value.Length);
            if (align)
            {
                writer.Write((byte)0);
            }

            writer.Write(value);
        }

        /// <summary>
        /// Encoded integer size.
        /// </summary>
        /// <param name="writer">The output.</param>
        /// <param name="size">The size.</param>
        private static void EncodeIntegerSize(BinaryWriter writer, int size)
        {
            if (size <= 0x7F)
            {
                writer.Write((byte)size);
            }
            else if (size <= 0xFF)
            {
                writer.Write((byte)0x81);
                writer.Write((byte)size);
            }
            else
            {
                writer.Write((byte)0x82);
                byte[] sizeBytes = BitConverter.GetBytes(size);
                writer.Write(sizeBytes[1]);
                writer.Write(sizeBytes[0]);
            }
        }

        /// <summary>
        /// Writes final sequence length.
        /// </summary>
        /// <param name="buffer">Buffer containing ASN.1 sequence.</param>
        private static void UpdateSequenceSize(byte[] buffer)
        {
            int size = buffer.Length;
            if (buffer[1] == 0x81)
            {
                size -= 3;
                byte[] sizeBytes = BitConverter.GetBytes(size);
                buffer[2] = sizeBytes[0];
            }
            else if (buffer[1] == 0x82)
            {
                size -= 4;
                byte[] sizeBytes = BitConverter.GetBytes(size);
                buffer[2] = sizeBytes[1];
                buffer[3] = sizeBytes[0];
            }
        }

        #endregion
    }
}
