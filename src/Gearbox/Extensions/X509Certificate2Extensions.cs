using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Gearbox.Extensions
{
    /// <summary>
    /// X509Certificate2 extension methods.
    /// </summary>
    public static class X509Certificate2Extensions
    {
        /// <summary>
        /// Default string builder capacity.
        /// </summary>
        private const int DefaultCapacity = 256;

        /// <summary>
        /// Subject alternative name OID
        /// </summary>
        private const string SubjectAltNameOid = "2.5.29.17";

        /// <summary>
        /// Enhanced key usage OID.
        /// </summary>
        private const string EnhancedKeyUsageOid = "2.5.29.37";

        /// <summary>
        /// Server authentication enhanced usage OID.
        /// </summary>
        private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

        /// <summary>
        /// Client authentication enhanced usage OID.
        /// </summary>
        private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

        /// <summary>
        /// Regex for matching alt subject name in format "RFC822 Name=someone@foo.com" and extracting email.
        /// </summary>
        private static readonly Regex CertEmailRegex = new Regex(
            @"^\s?RFC822\s+Name\s?=\s?(?<result>.*)$",
            RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);

        /// <summary>
        /// Regex for matching alt subject name in format "DNS Name=server.foo.com" and extracting DNS name.
        /// </summary>
        private static readonly Regex CertDnsNameRegex = new Regex(
            @"^\s?DNS\s+Name\s?=\s?(?<result>.*)$",
            RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);

        /// <summary>
        /// Regex for matching alt subject name in format "Other Name:Principal Name=test@foo.com" and extracting UPN.
        /// </summary>
        private static readonly Regex CertUpnRegex = new Regex(
            @"^\s?Other Name\s?:\s?Principal Name\s?=\s?(?<result>.*)$",
            RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);

        /// <summary>
        /// Regex match group name used below.
        /// </summary>
        private const string RegexGroupName = "result";

        /// <summary>
        /// Extension methods.
        /// </summary>
        /// <param name="certificate">Certificate instance.</param>
        extension(X509Certificate2 certificate)
        {
            /// <summary>
            /// Retrieves the UPN of the certificate from SAN, if present.
            /// </summary>
            /// <returns>List of UPNs found in SAN or empty list.</returns>
            public List<string> GetUserPrincipalName()
            {
                return certificate.GetSubjectAltNameValue(CertUpnRegex);
            }

            /// <summary>
            /// Retrieves the email address from SAN of the certificate, if present.
            /// </summary>
            /// <returns>List of email addresses found in SAN or empty list.</returns>
            public List<string> GetUserEmailAddress()
            {
                return certificate.GetSubjectAltNameValue(CertEmailRegex);
            }

            /// <summary>
            /// Retrieves DNS name from SAN of the certificate, if present.
            /// </summary>
            /// <returns>List of DNS names found in SAN or empty list.</returns>
            public List<string> GetDnsName()
            {
                return certificate.GetSubjectAltNameValue(CertDnsNameRegex);
            }

            /// <summary>
            /// Returns raw Subject Alternative Name value from the certificate.
            /// </summary>
            /// <returns>Raw subject alternative name value or null.</returns>
            public string? GetSubjectAltName()
            {
                foreach (X509Extension extension in certificate.Extensions)
                {
                    if (string.Equals(extension.Oid?.Value, SubjectAltNameOid, StringComparison.Ordinal))
                    {
                        return extension.Format(false);
                    }
                }

                return null;
            }

            /// <summary>
            /// Checks if the certificate has not expired.
            /// </summary>
            /// <returns>True if the certificate has not expired.</returns>
            public bool IsExpired()
            {
                DateTime now = DateTime.UtcNow;
                return certificate.NotAfter.ToUniversalTime() <= now || certificate.NotBefore.ToUniversalTime() >= now;
            }

            /// <summary>
            /// Checks of certificate is self-singed.
            /// </summary>
            /// <returns>true if certificate is self-signed; false otherwise.</returns>
            public bool IsSelfSigned()
            {
                return certificate.SubjectName.RawData.SequenceEqual(certificate.IssuerName.RawData);
            }

            /// <summary>
            /// Validates certificate by checking expiration and building the chain.
            /// </summary>
            /// <returns>true if certificate is valid; false otherwise.</returns>
            public bool IsValidCertificate()
            {
                return !certificate.IsExpired() && certificate.BuildChain();
            }

            /// <summary>
            /// Builds X.509 certificate chain. 
            /// </summary>
            /// <returns>true if chain was built successfully; false otherwise.</returns>
            public bool BuildChain()
            {
                using (X509Chain x509Chain = new X509Chain(true))
                {
                    x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    if (x509Chain.Build(certificate))
                    {
                        foreach (X509ChainStatus status in x509Chain.ChainStatus)
                        {
                            // Chain.Build() can return true even though errors occurred.
                            // We need to check each ChainStatus for errors.
                            if (status.Status != X509ChainStatusFlags.NoError)
                            {
                                return false;
                            }
                        }

                        return true;
                    }
                }

                return false;
            }

            /// <summary>
            /// Checks if certificate has server authentication usage.
            /// </summary>
            /// <returns>true if certificate has server authentication usage; false otherwise.</returns>
            public bool HasServerAuthenticationUsage()
            {
                return certificate.HasEnhancedKeyUsage(ServerAuthOid);
            }

            /// <summary>
            /// Checks if certificate has client authentication usage.
            /// </summary>
            /// <returns>true if certificate has client authentication usage; false otherwise.</returns>
            public  bool HasClientAuthenticationUsage()
            {
                return certificate.HasEnhancedKeyUsage(ClientAuthOid);
            }

            /// <summary>
            /// Determines of certificate had specified enhanced key usage. 
            /// </summary>
            /// <param name="usageOid">Enhanced usage OID.</param>
            /// <returns>true if certificate has specified enhanced usage; false otherwise.</returns>
            public bool HasEnhancedKeyUsage(string usageOid)
            {
                foreach (X509Extension extension in certificate.Extensions)
                {
                    if (extension.Oid?.Value == EnhancedKeyUsageOid)
                    {
                        X509EnhancedKeyUsageExtension ekuExtension = (X509EnhancedKeyUsageExtension)extension;
                        foreach (Oid oid in ekuExtension.EnhancedKeyUsages)
                        {
                            if (oid.Value == usageOid)
                            {
                                return true;
                            }
                        }
                    }
                }

                return false;
            }

            /// <summary>
            /// Builds the chain for the specified certificate and throws exception in case of error.
            /// The certificate itself is not included in the chain unless it is self-signed.
            /// </summary>
            /// <returns>Chains of issuer certificates.</returns>
            public ICollection<X509Certificate2> BuildIssuerChain()
            {
                using (X509Chain x509Chain = new X509Chain(true))
                {
                    x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                    bool success = x509Chain.Build(certificate) &&
                                   x509Chain.ChainStatus.All(x => x.Status == X509ChainStatusFlags.NoError);

                    if (success)
                    {
                        bool selfSigned = certificate.IsSelfSigned();

                        List<X509Certificate2> chain = new List<X509Certificate2>(x509Chain.ChainElements.Count);
                        foreach (X509ChainElement chainElement in x509Chain.ChainElements)
                        {
                            if (selfSigned || chainElement.Certificate.Thumbprint != certificate.Thumbprint)
                            {
                                chain.Add(chainElement.Certificate);
                            }
                        }

                        return chain;
                    }
                }

                throw new CryptographicException($"Failed to build X509 chain for certificate with thumbprint {certificate.Thumbprint}.");
            }

            /// <summary>
            /// Builds the chain for the specified certificate and encoded it in PEM format.
            /// The certificate itself is not included in the chain unless it is self-signed.
            /// </summary>
            /// <returns>PEM encoded certificate chain.</returns>
            public string BuildIssuerChainPem()
            {
                StringBuilder builder = new StringBuilder(DefaultCapacity * 2);
                ICollection<X509Certificate2> chain = certificate.BuildIssuerChain();
                foreach (X509Certificate2 cert in chain)
                {
                    builder.AppendLine(cert.ExportPem());
                }

                return builder.ToString();
            }

            /// <summary>
            /// Exports certificate in PEM format.
            /// </summary>
            /// <returns>String containing certificate in PEM format.</returns>
            public string ExportPem()
            {
                StringBuilder builder = new StringBuilder(DefaultCapacity);
                builder.AppendLine(Certificate.PemCertHeader);
                builder.AppendLine(Convert.ToBase64String(certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                builder.Append(Certificate.PemCertFooter);
                return builder.ToString();
            }

            /// <summary>
            /// Exports certificate's private key in PEM format.
            /// </summary>
            /// <returns>String containing private key in PEM format.</returns>
            public string ExportPrivateKeyPem()
            {
                // We expect certificate to contain private key and it should be RSA
                RSAParameters rsaParameters = default;
                RSA? rsa = certificate.GetRSAPrivateKey();
                if (rsa == null)
                {
                    throw new InvalidOperationException("RSA key is expected.");
                }

                rsaParameters = rsa.ExportParameters(true);
                string pem = RsaKeyHelper.EncodeParametersPem(rsaParameters);
                X509Certificate2.ClearRsaParameters(rsaParameters);
                return pem;
            }

            /// <summary>
            /// Gets subject alternative name value matching supplied regex.
            /// </summary>
            /// <param name="regex">The regex.</param>
            /// <returns>Matching value(s) or empty list.</returns>
            private List<string> GetSubjectAltNameValue(Regex regex)
            {
                List<string> result = new List<string>();
                string? san = certificate.GetSubjectAltName();
                if (!string.IsNullOrEmpty(san))
                {
                    // It is possible to have multiple SAN values separated by ','
                    string[] altNames = san.Split(',');
                    foreach (string altName in altNames)
                    {
                        string value = altName.Trim();
                        Match match = regex.Match(value);
                        if (match.Success)
                        {
                            string val = match.Groups[RegexGroupName].Value;
                            result.Add(val.Trim());
                        }
                    }
                }

                return result;
            }

            /// <summary>
            /// Overwrites all values with zeros and then clears them.
            /// </summary>
            /// <param name="parameters">The RSAParameters instance.</param>
            private static void ClearRsaParameters(RSAParameters parameters)
            {
                X509Certificate2.EraseBufferContent(parameters.Modulus);
                X509Certificate2.EraseBufferContent(parameters.D);
                X509Certificate2.EraseBufferContent(parameters.DP);
                X509Certificate2.EraseBufferContent(parameters.DQ);
                X509Certificate2.EraseBufferContent(parameters.Exponent);
                X509Certificate2.EraseBufferContent(parameters.InverseQ);
                X509Certificate2.EraseBufferContent(parameters.P);
                X509Certificate2.EraseBufferContent(parameters.Q);
            }

            /// <summary>
            /// Erases buffer's content by overwriting it with zeros.
            /// </summary>
            /// <param name="prop">Byte array property to erase.</param>
            private static void EraseBufferContent(byte[]? prop)
            {
                if (prop is not null)
                {
                    for (int i = 0; i < prop.Length; ++i)
                    {
                        prop[i] = 0;
                    }
                }
            }
        }

        /// <summary>
        /// RSA key helper.
        /// </summary>
        internal static class RsaKeyHelper
        {
            /// <summary>
            /// Encodes RSA private key parameters in PEM format.
            /// </summary>
            /// <param name="rsaParameters">The private key parameters.</param>
            /// <returns>String containing private key in PEM format.</returns>
            public static string EncodeParametersPem(RSAParameters rsaParameters)
            {
                byte[] sequence = EncodeRsaPrivateKey(rsaParameters);
                StringBuilder builder = new StringBuilder(512);
                builder.AppendLine(Certificate.PemRsaKeyHeader);
                builder.AppendLine(Convert.ToBase64String(sequence, Base64FormattingOptions.InsertLineBreaks));
                builder.Append(Certificate.PemRsaKeyFooter);
                return builder.ToString();
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
                // https://en.wikipedia.org/wiki/RSA_(cryptosystem)
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
                // .NET 4.6.2 has only one BigInteger constructor receiving byte array.
                // .NET Core has additional overload allowing to specify byte order and sign.
                // Since we have to target both we are reversing byte order and setting sign manually.
                // We also have to remove zero byte used to designate value as positive.
                byte[] bytes = bi.ToByteArray();
                if (bytes[bytes.Length - 1] == 0)
                {
                    Array.Resize(ref bytes, bytes.Length - 1);
                }

                Array.Reverse(bytes);
                return bytes;
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
                int approxSequenceLen = rsa.D.Length +
                                rsa.DP.Length +
                                rsa.DQ.Length +
                                rsa.Exponent.Length +
                                rsa.InverseQ.Length +
                                rsa.Modulus.Length +
                                rsa.P.Length +
                                rsa.Q.Length +
                                18;

                using (MemoryStream ms = new MemoryStream())
                using (BinaryWriter writer = new BinaryWriter(ms))
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

                    // Our initial sequence length may is probably incorrect due to padding.
                    // Fix it before returning.
                    UpdateSequenceSize(buffer);
                    return buffer;
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
}
