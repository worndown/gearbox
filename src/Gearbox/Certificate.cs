using System.Security.Cryptography.X509Certificates;
using System.Text;
using Gearbox.Extensions;

namespace Gearbox
{
    /// <summary>
    /// X509 certificate helpers.
    /// </summary>
    public static class Certificate
    {
        /// <summary>
        /// Default string builder capacity.
        /// </summary>
        private const int DefaultCapacity = 256;

        /// <summary>
        /// PEM certificate header.
        /// </summary>
        public const string PemCertHeader = "-----BEGIN CERTIFICATE-----";

        /// <summary>
        /// PEM certificate footer.
        /// </summary>
        public const string PemCertFooter = "-----END CERTIFICATE-----";

        /// <summary>
        /// PEM RSA key header.
        /// </summary>
        public const string PemRsaKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";

        /// <summary>
        /// PEM RSA key footer.
        /// </summary>
        public const string PemRsaKeyFooter = "-----END RSA PRIVATE KEY-----";

        /// <summary>
        /// Finds a valid certificate with the specified thumbprint in the specified store location.
        /// </summary>
        /// <param name="thumbprint">Thumbprint to match.</param>
        /// <param name="storeLocation">Store location.</param>
        /// <returns>Certificate with specified thumbprint or null if requested certificate wasn't found.</returns>
        /// <remarks>The caller must dispose the returned certificate.</remarks>
        public static X509Certificate2? FindByThumbprint(string thumbprint, StoreLocation storeLocation)
        {
            using (X509Store store = new X509Store(storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                return FindCertificateByThumbprint(store, thumbprint);
            }
        }

        /// <summary>
        /// Finds a valid certificate with the specified thumbprint in the specified store and location.
        /// </summary>
        /// <param name="thumbprint">Thumbprint to match.</param>
        /// <param name="storeName">Store name.</param>
        /// <param name="storeLocation">Store location.</param>
        /// <returns>Certificate with specified thumbprint or null if requested certificate wasn't found.</returns>
        /// <remarks>The caller must dispose the returned certificate.</remarks>
        public static X509Certificate2? FindByThumbprint(string thumbprint, StoreName storeName, StoreLocation storeLocation)
        {
            using (X509Store store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                return FindCertificateByThumbprint(store, thumbprint);
            }
        }

        /// <summary>
        /// Finds a valid certificate with the specified UPN in the specified store location.
        /// </summary>
        /// <param name="upn">UPN to match.</param>
        /// <param name="storeLocation">Store location.</param>
        /// <returns>Certificate with the specified UPN or null if requested certificate wasn't found.</returns>
        /// <remarks>The caller must dispose the returned certificate.</remarks>
        public static X509Certificate2? FindByUpn(string upn, StoreLocation storeLocation)
        {
            using (X509Store store = new X509Store(storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                return FindCertificateByUpn(store, upn);
            }
        }

        /// <summary>
        /// Finds a valid certificate with the specified UPN in the specified store and location.
        /// </summary>
        /// <param name="upn">UPN to match.</param>
        /// <param name="storeName">Store name.</param>
        /// <param name="storeLocation">Store location.</param>
        /// <returns>Certificate with the specified UPN or null if requested certificate wasn't found.</returns>
        /// <remarks>The caller must dispose the returned certificate.</remarks>
        public static X509Certificate2? FindByUpn(string upn, StoreName storeName, StoreLocation storeLocation)
        {
            using (X509Store store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                return FindCertificateByUpn(store, upn);
            }
        }

        /// <summary>
        /// Finds a valid certificate with the specified subject name in the specified store location.
        /// </summary>
        /// <param name="name">Subject name to match.</param>
        /// <param name="storeLocation">Store location.</param>
        /// <returns>Certificate with the specified subject or null if requested certificate wasn't found.</returns>
        /// <remarks>The caller must dispose the returned certificate.</remarks>
        public static X509Certificate2? FindBySubjectName(string name, StoreLocation storeLocation)
        {
            using (X509Store store = new X509Store(storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                return FindCertificateBySubjectName(store, name);
            }
        }

        /// <summary>
        /// Finds a valid certificate with the specified subject name in the specified store and location.
        /// </summary>
        /// <param name="name">Subject name to match.</param>
        /// <param name="storeName">Store name.</param>
        /// <param name="storeLocation">Store location.</param>
        /// <returns>Certificate with the specified subject name or null if requested certificate wasn't found.</returns>
        /// <remarks>The caller must dispose the returned certificate.</remarks>
        public static X509Certificate2? FindBySubjectName(string name, StoreName storeName, StoreLocation storeLocation)
        {
            using (X509Store store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                return FindCertificateBySubjectName(store, name);
            }
        }

        /// <summary>
        /// Exports all trusted, non-expired root certificates in PEM format.
        /// </summary>
        /// <returns>String containing all trusted root certificates in PEM format.</returns>
        public static string ExportTrustedRootCertificatesPem()
        {
            StringBuilder builder = new StringBuilder(DefaultCapacity * 4);
            using X509Store store = new X509Store(StoreName.Root);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certificates = store.Certificates;
            try
            {
                foreach (X509Certificate2 cert in certificates)
                {
                    if (!cert.IsExpired())
                    {
                        builder.AppendLine(cert.ExportPem());
                        builder.AppendLine();
                    }
                }

                return builder.ToString();
            }
            finally
            {
                foreach (X509Certificate2 cert in certificates)
                {
                    cert.Dispose();
                }
            }
        }

        /// <summary>
        /// Creates certificate instance from PEM string.
        /// </summary>
        /// <param name="pem">PEM encoded certificate.</param>
        /// <returns>X.509 certificate instance.</returns>
        /// <remarks>The caller must dispose the returned certificate. Private keys in the PEM are not imported.</remarks>
        public static X509Certificate2 CreateFromPem(string pem)
        {
            ArgumentException.ThrowIfNullOrEmpty(pem);

            int start = pem.IndexOf(PemCertHeader, StringComparison.Ordinal);
            if (start < 0)
            {
                throw new FormatException("Not a valid PEM encoded certificate.");
            }

            start += PemCertHeader.Length;
            int end = pem.IndexOf(PemCertFooter, start, StringComparison.Ordinal);
            if (end < 0)
            {
                throw new FormatException("Not a valid PEM encoded certificate.");
            }

            byte[] certBytes = Convert.FromBase64String(pem.Substring(start, end - start));
            return X509CertificateLoader.LoadCertificate(certBytes);
        }

        /// <summary>
        /// Finds a valid certificate in the specified store by thumbprint.
        /// </summary>
        /// <param name="store">Certificate store to search.</param>
        /// <param name="thumbprint">Thumbprint to match.</param>
        /// <returns>Certificate with the specified thumbprint or null if certificate wasn't found.</returns>
        private static X509Certificate2? FindCertificateByThumbprint(X509Store store, string thumbprint)
        {
            return FindCertificate(store,
                certificate => string.Equals(certificate.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase),
                newestMatch: false);
        }

        /// <summary>
        /// Finds a valid certificate in the specified store by subject name.
        /// </summary>
        /// <param name="store">Certificate store to search.</param>
        /// <param name="name">Subject name to match.</param>
        /// <returns>Certificate with the specified subject name or null if certificate wasn't found.</returns>
        private static X509Certificate2? FindCertificateBySubjectName(X509Store store, string name)
        {
            return FindCertificate(store,
                certificate => string.Equals(certificate.SubjectName.Name, name, StringComparison.OrdinalIgnoreCase),
                newestMatch: true);
        }

        /// <summary>
        /// Finds a valid certificate with the specified UPN in the specified store.
        /// </summary>
        /// <param name="store">Certificate store to search.</param>
        /// <param name="upn">UPN to match.</param>
        /// <returns>Certificate with the specified UPN or null if requested certificate wasn't found.</returns>
        private static X509Certificate2? FindCertificateByUpn(X509Store store, string upn)
        {
            return FindCertificate(store,
                certificate => certificate.GetUserPrincipalName().Contains(upn),
                newestMatch: true);
        }

        /// <summary>
        /// Finds a valid certificate and disposes every store certificate that is not returned.
        /// </summary>
        private static X509Certificate2? FindCertificate(X509Store store, Predicate<X509Certificate2> matches, bool newestMatch)
        {
            X509Certificate2Collection certificates = store.Certificates;
            X509Certificate2? result = null;
            try
            {
                X509Certificate2? match = null;
                foreach (X509Certificate2 certificate in certificates)
                {
                    if (matches(certificate) && certificate.IsValidCertificate())
                    {
                        if (match == null || certificate.NotBefore > match.NotBefore)
                        {
                            match = certificate;
                        }

                        if (!newestMatch)
                        {
                            break;
                        }
                    }
                }

                result = match;
                return result;
            }
            finally
            {
                foreach (X509Certificate2 certificate in certificates)
                {
                    if (!ReferenceEquals(certificate, result))
                    {
                        certificate.Dispose();
                    }
                }
            }
        }
    }
}
