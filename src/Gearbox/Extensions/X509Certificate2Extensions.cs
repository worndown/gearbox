using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Gearbox.Cryptography;

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
        /// User principal name otherName OID.
        /// </summary>
        private const string UserPrincipalNameOid = "1.3.6.1.4.1.311.20.2.3";

        /// <summary>
        /// Extension methods.
        /// </summary>
        /// <param name="certificate">Certificate instance.</param>
        extension(X509Certificate2 certificate)
        {
            /// <summary>
            /// Retrieves the UPN of the certificate from SAN, if present.
            /// </summary>
            /// <returns>List of UPNs found in SAN or an empty list if SAN is absent or malformed.</returns>
            public List<string> GetUserPrincipalName()
            {
                return certificate.GetSubjectAltNameValue(0);
            }

            /// <summary>
            /// Retrieves the email address from SAN of the certificate, if present.
            /// </summary>
            /// <returns>List of email addresses found in SAN or an empty list if SAN is absent or malformed.</returns>
            public List<string> GetUserEmailAddress()
            {
                return certificate.GetSubjectAltNameValue(1);
            }

            /// <summary>
            /// Retrieves DNS name from SAN of the certificate, if present.
            /// </summary>
            /// <returns>List of DNS names found in SAN or an empty list if SAN is absent or malformed.</returns>
            public List<string> GetDnsName()
            {
                return certificate.GetSubjectAltNameValue(2);
            }

            /// <summary>
            /// Returns the platform-formatted Subject Alternative Name value from the certificate.
            /// </summary>
            /// <returns>Formatted subject alternative name value or null.</returns>
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
            /// Checks if the certificate is expired or is not yet valid.
            /// </summary>
            /// <returns>True if the current time is outside the certificate's validity period.</returns>
            public bool IsExpired()
            {
                DateTime now = DateTime.UtcNow;
                return certificate.NotAfter.ToUniversalTime() <= now || certificate.NotBefore.ToUniversalTime() >= now;
            }

            /// <summary>
            /// Checks if the certificate's subject and issuer names are identical.
            /// </summary>
            /// <returns>true if the subject and issuer names match; false otherwise.</returns>
            /// <remarks>This compares names without verifying the certificate's signature.</remarks>
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
            public bool HasClientAuthenticationUsage()
            {
                return certificate.HasEnhancedKeyUsage(ClientAuthOid);
            }

            /// <summary>
            /// Determines if the certificate has the specified enhanced key usage.
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
            /// <returns>Chain of issuer certificates.</returns>
            /// <remarks>The caller must dispose each returned certificate.</remarks>
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
            /// Builds the chain for the specified certificate and encodes it in PEM format.
            /// The certificate itself is not included in the chain unless it is self-signed.
            /// </summary>
            /// <returns>PEM encoded certificate chain.</returns>
            public string BuildIssuerChainPem()
            {
                StringBuilder builder = new StringBuilder(DefaultCapacity * 2);
                ICollection<X509Certificate2> chain = certificate.BuildIssuerChain();
                try
                {
                    foreach (X509Certificate2 cert in chain)
                    {
                        builder.AppendLine(cert.ExportPem());
                    }

                    return builder.ToString();
                }
                finally
                {
                    foreach (X509Certificate2 cert in chain)
                    {
                        cert.Dispose();
                    }
                }
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
                using RSA? rsa = certificate.GetRSAPrivateKey();
                if (rsa == null)
                {
                    throw new InvalidOperationException("RSA key is expected.");
                }

                RSAParameters rsaParameters = rsa.ExportParameters(true);
                try
                {
                    return RSAKey.EncodeParametersPem(rsaParameters);
                }
                finally
                {
                    X509Certificate2.ClearRsaParameters(rsaParameters);
                }
            }

            /// <summary>
            /// Decodes subject alternative names directly from the DER-encoded extension.
            /// </summary>
            /// <param name="nameType">GeneralName tag: 0 for UPN, 1 for email, or 2 for DNS.</param>
            /// <returns>Matching values or an empty list if SAN is absent or malformed.</returns>
            private List<string> GetSubjectAltNameValue(int nameType)
            {
                List<string> result = new List<string>();
                X509Extension? extension = certificate.Extensions[SubjectAltNameOid];
                if (extension == null)
                {
                    return result;
                }

                try
                {
                    AsnReader reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
                    AsnReader names = reader.ReadSequence();
                    reader.ThrowIfNotEmpty();
                    while (names.HasData)
                    {
                        Asn1Tag tag = names.PeekTag();
                        if (tag.TagClass != TagClass.ContextSpecific || tag.TagValue > 8)
                        {
                            throw new AsnContentException();
                        }

                        if (tag.TagValue == 1 || tag.TagValue == 2)
                        {
                            string value = names.ReadCharacterString(
                                UniversalTagNumber.IA5String,
                                new Asn1Tag(TagClass.ContextSpecific, tag.TagValue));
                            if (tag.TagValue == nameType)
                            {
                                result.Add(value);
                            }
                        }
                        else if (tag.TagValue == 0)
                        {
                            Asn1Tag otherNameTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
                            AsnReader otherName = names.ReadSequence(otherNameTag);
                            string oid = otherName.ReadObjectIdentifier();
                            AsnReader value = otherName.ReadSequence(otherNameTag);
                            if (oid == UserPrincipalNameOid)
                            {
                                string upn = value.ReadCharacterString(UniversalTagNumber.UTF8String);
                                if (nameType == 0)
                                {
                                    result.Add(upn);
                                }
                            }
                            else
                            {
                                value.ReadEncodedValue();
                            }

                            value.ThrowIfNotEmpty();
                            otherName.ThrowIfNotEmpty();
                        }
                        else
                        {
                            names.ReadEncodedValue();
                        }
                    }
                }
                catch (AsnContentException)
                {
                    // A malformed extension must not return partially decoded names.
                    return [];
                }

                return result;
            }

            /// <summary>
            /// Overwrites all RSA parameter buffers with zeros.
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
                    CryptographicOperations.ZeroMemory(prop);
                }
            }
        }
    }
}
