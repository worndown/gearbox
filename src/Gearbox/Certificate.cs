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
            X509Store store = new X509Store(StoreName.Root);
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (!cert.IsExpired())
                {
                    builder.AppendLine(cert.ExportPem());
                    builder.AppendLine();
                }
            }

            return builder.ToString();
        }

        /// <summary>
        /// Creates certificate instance from PEM string.
        /// </summary>
        /// <param name="pem">PEM encoded certificate.</param>
        /// <returns>X.509 certificate instance.</returns>
        public static X509Certificate2 CreateFromPem(string pem)
        {
            ArgumentException.ThrowIfNullOrEmpty(pem);

            int start = pem.IndexOf(PemCertHeader, StringComparison.Ordinal);
            int end = pem.IndexOf(PemCertFooter, start, StringComparison.Ordinal);
            if (start < 0 || end < 0)
            {
                throw new FormatException("Not a valid PEM encoded certificate.");
            }

            start += PemCertHeader.Length;
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
            foreach (X509Certificate2 certificate in store.Certificates)
            {
                if (string.Compare(certificate.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase) == 0 &&
                    certificate.IsValidCertificate())
                {
                    return certificate;
                }
            }

            return null;
        }

        /// <summary>
        /// Finds a valid certificate in the specified store by subject name.
        /// </summary>
        /// <param name="store">Certificate store to search.</param>
        /// <param name="name">Subject name to match.</param>
        /// <returns>Certificate with the specified subject name or null if certificate wasn't found.</returns>
        private static X509Certificate2? FindCertificateBySubjectName(X509Store store, string name)
        {
            X509Certificate2? match = null;

            foreach (X509Certificate2 certificate in store.Certificates)
            {
                if (string.Compare(certificate.SubjectName.Name, name, StringComparison.OrdinalIgnoreCase) == 0 &&
                    certificate.IsValidCertificate())
                {
                    if (match == null || certificate.NotBefore > match.NotBefore)
                    {
                        match = certificate;
                    }
                }
            }

            return match;
        }

        /// <summary>
        /// Finds a valid certificate with the specified UPN in the specified store.
        /// </summary>
        /// <param name="store">Certificate store to search.</param>
        /// <param name="upn">UPN to match.</param>
        /// <returns>Certificate with the specified UPN or null if requested certificate wasn't found.</returns>
        private static X509Certificate2? FindCertificateByUpn(X509Store store, string upn)
        {
            X509Certificate2? match = null;

            foreach (X509Certificate2 certificate in store.Certificates)
            {
                List<string> certUpns = certificate.GetUserPrincipalName();
                if (certUpns.Count == 0)
                {
                    continue;
                }

                foreach (string certUpn in certUpns)
                {
                    if (certUpn == upn && certificate.IsValidCertificate())
                    {
                        if (match == null || certificate.NotBefore > match.NotBefore)
                        {
                            match = certificate;
                            break;
                        }
                    }
                }
            }

            return match;
        }
    }
}
