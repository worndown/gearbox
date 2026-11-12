using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Gearbox.Extensions;

namespace Gearbox.Tests
{
    [TestClass]
    public class CertificateTests
    {
        #region PEM encoded certificates

        private const string CertPem =
            @"-----BEGIN CERTIFICATE-----
MIIFIDCCBAigAwIBAgIIVeJpKq3g9M8wDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJXQTERMA8GA1UEBxMISXNzYXF1YWgxDzANBgNVBAoT
BkZvb2JhcjEUMBIGA1UECxMLRW5naW5lZXJpbmcxFzAVBgNVBAMTDnd3dy5mb29i
YXIuY29tMSUwIwYJKoZIhvcNAQkBFhZlbmdpbmVlcmluZ0Bmb29iYXIuY29tMB4X
DTIxMDUyMjE5MzYwMFoXDTQxMDUyMjE5MzYwMFowgZQxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIEwJXQTERMA8GA1UEBxMISXNzYXF1YWgxDzANBgNVBAoTBkZvb2JhcjEU
MBIGA1UECxMLRW5naW5lZXJpbmcxFzAVBgNVBAMTDnd3dy5mb29iYXIuY29tMSUw
IwYJKoZIhvcNAQkBFhZlbmdpbmVlcmluZ0Bmb29iYXIuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwULF/l0SdrL6QZOF9BRw/Vu//1aZtAhSJQvI
FcMgoIXPv76bnlqFAdbFaLmC46cCw5Nv9Ve5ooBKbU9apK2x1rIRfltMv9rm+LkB
uyS9dy90wnPr+DEUpAxaLT8TTjVGAvuk+J7alzHnIwcgv1nxCwYl1I7xWPY3Nx+w
/HMPpQX3b6eamaFfZgb7pjDNWzSPBCcscDSlcawGjR5o46M5WemeEzaQAlW3/EBQ
E8vLxBOeg0X2Ek/0qV/xrLdVzicJ6N1XCzBVgcA3Q5huWg5R+orY/Oo9ZeB6GTud
EnqaWMwnHKkRH1UuNLUUts4HcixVbiVL5p9eABUjQxOwnIgLTwIDAQABo4IBcjCC
AW4wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUboiz3xlo32maA+fqGGaCz7eklAEw
HwYDVR0jBBgwFoAUboiz3xlo32maA+fqGGaCz7eklAEwCwYDVR0PBAQDAgP4MB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBgBgNVHREEWTBXgg5mdHAuZm9v
YmFyLmNvbYIPbWFpbC5mb29iYXIuY29tgRJzdXBwb3J0QGZvb2Jhci5jb22gIAYK
KwYBBAGCNxQCA6ASDBBhZG1pbkBmb29iYXIuY29tMBwGA1UdEgQVMBOCEWlzc3Vl
ci5mb29iYXIuY29tMDIGA1UdHwQrMCkwJ6AloCOGIWZvb2JhLmNvbS9kaXN0cmli
dXRpb24vcG9pbnQuaHRtbDArBggrBgEFBQcBAQQfMB0wGwYIKwYBBQUHMAGBD2lu
Zm9AZm9vYmFyLmNvbTARBglghkgBhvhCAQEEBAMCBeAwDQYJKoZIhvcNAQELBQAD
ggEBACo98o1sBOTwHgljhrLTSmx6EUnmZjgGyAJJz62dgVyMT2+l2f8d/BLORBKg
xtqXj9oPwmlFfd19M5py2mCWPs+MwONkcUV++Y7p6HiyvlQQAhkUywHf6WnK27Z4
afd2jrzjJFEZj5GoIH0piFT5vWsTXHDKYfRdzr9FU6L38BemIs4FbGLSd43KEizj
5vzC6ccHKcmOkLHCV+GTGX7FA8NmWajBeQIYE06aEWwJgPAVXsHuB5cfDyR95Z/w
7BYGItkG8DRj0BIIdbpKxhPa4vZScXiNydT6pph9FEtzFcGgw4KwjZfxVsvvpGTe
VeTIr1P7uVWABgJ7i+DkbVriKKk=
-----END CERTIFICATE-----";

        private const string CertKeyPem =
            @"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwULF/l0SdrL6QZOF9BRw/Vu//1aZtAhSJQvIFcMgoIXPv76b
nlqFAdbFaLmC46cCw5Nv9Ve5ooBKbU9apK2x1rIRfltMv9rm+LkBuyS9dy90wnPr
+DEUpAxaLT8TTjVGAvuk+J7alzHnIwcgv1nxCwYl1I7xWPY3Nx+w/HMPpQX3b6ea
maFfZgb7pjDNWzSPBCcscDSlcawGjR5o46M5WemeEzaQAlW3/EBQE8vLxBOeg0X2
Ek/0qV/xrLdVzicJ6N1XCzBVgcA3Q5huWg5R+orY/Oo9ZeB6GTudEnqaWMwnHKkR
H1UuNLUUts4HcixVbiVL5p9eABUjQxOwnIgLTwIDAQABAoIBAEU+IGRfgnMG80U1
jwQBou4Txnm81Hs9k/jz/K9XZ0Q8TU/9AhK9ifQ7uCUqemwIdaQPGkkEMl23q3L4
wJhKJ3KuADiOi7QdwS2SU71yj3O5jBLzp7MYGrYgOtsFQ2x9B+Wftd7iQ51yYscZ
EbGdjxCNFlbPFEf0h5n3f9kjfJJ6LlbbsRFVuihRcz8SsGKJZiTaJPGt0FP0/l7e
4ZAAt/VZTPrlJ8N1ggPvTKdWvcYKJ90v+Y/EB+XM6XtbHLydvGROvd8lrNGfxHoV
8Z/e8nJovV1l0vbx0W8Zk170GO+Tuq6wnlhMZY/FgC4FFfYugZaJaO7bGv7S9fGb
DJ1nfYECgYEA5Lev5eAJln/QyziiAH359NLO5A9gaVKACKfhpCU2MTCp7xmLSvOm
VUv1TuKKbbSdYlrb4q3hl+7nAiy10tbdqhj4GDEUklGpJ6BXnpTIeiGz4/146dLN
/+4l+LAuml3ch4r2Ua9wqoDQLL/Yke+tteC+elS/neIV9AlsTosE/I8CgYEA2FBZ
vc5wytQYms7lOtAPpnSLV047bSF1NX0KQ4TCh3fUppbTe00ZO2cA32NN2XeoPA5W
ZkwXJXzVBnq7yh5B9eT9gGB2zFIhybjV3KX8zeZu110PT0VDjkuKfT/XD8gJRh76
xNWuOM0Zk4fT00HAOccWH+ahDVyWkTiTF1wo5UECgYBdGLesZgkBDX27eo3WjXCU
ysoT4n5n4IDlBRC/c7YfR6OkA03DcHGf/o8XUPbvuLjnM/yUxBozcbbuF6za6ULI
3ej+T9wDwuGLk6SWlBEWRWmnv6Db7EaViiZCl9QgWVxOf63LihHeFRinXl+U525Z
veVKffyRE1nEP6GqRsP82QKBgQCV02mlNyUWx7tXFrDdgJkmcRjGWvB8US1O5BHE
3GKk1BIdZOCMScWNSHXpRG36j4+eMUwUxOVPWNxwBXimsTh8qaQQVEBUmxq+DuFK
WEn3D4F8d/+Pp2j4WUhOInbCfoo14GVPCrYGr8DkV7MXYzZSjpu7ctHgYF4Frgrr
pjDJQQKBgC7mGqWxtLA+OjiaZtbOHYz6JEJerqS5aoh+d3jSyQ6VRe7KTF7ZFypm
hRn0ir5MBTi6snerzukEpLtIXhuBbCYMECk1uxBWNWP49oe38saFJQfb/juOVFRW
xeoSReDP7orgWC8rEZm4mBgYPX5UtKCVsb7KLpNdybi+IdiSKfua
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIFIDCCBAigAwIBAgIIVeJpKq3g9M8wDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJXQTERMA8GA1UEBxMISXNzYXF1YWgxDzANBgNVBAoT
BkZvb2JhcjEUMBIGA1UECxMLRW5naW5lZXJpbmcxFzAVBgNVBAMTDnd3dy5mb29i
YXIuY29tMSUwIwYJKoZIhvcNAQkBFhZlbmdpbmVlcmluZ0Bmb29iYXIuY29tMB4X
DTIxMDUyMjE5MzYwMFoXDTQxMDUyMjE5MzYwMFowgZQxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIEwJXQTERMA8GA1UEBxMISXNzYXF1YWgxDzANBgNVBAoTBkZvb2JhcjEU
MBIGA1UECxMLRW5naW5lZXJpbmcxFzAVBgNVBAMTDnd3dy5mb29iYXIuY29tMSUw
IwYJKoZIhvcNAQkBFhZlbmdpbmVlcmluZ0Bmb29iYXIuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwULF/l0SdrL6QZOF9BRw/Vu//1aZtAhSJQvI
FcMgoIXPv76bnlqFAdbFaLmC46cCw5Nv9Ve5ooBKbU9apK2x1rIRfltMv9rm+LkB
uyS9dy90wnPr+DEUpAxaLT8TTjVGAvuk+J7alzHnIwcgv1nxCwYl1I7xWPY3Nx+w
/HMPpQX3b6eamaFfZgb7pjDNWzSPBCcscDSlcawGjR5o46M5WemeEzaQAlW3/EBQ
E8vLxBOeg0X2Ek/0qV/xrLdVzicJ6N1XCzBVgcA3Q5huWg5R+orY/Oo9ZeB6GTud
EnqaWMwnHKkRH1UuNLUUts4HcixVbiVL5p9eABUjQxOwnIgLTwIDAQABo4IBcjCC
AW4wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUboiz3xlo32maA+fqGGaCz7eklAEw
HwYDVR0jBBgwFoAUboiz3xlo32maA+fqGGaCz7eklAEwCwYDVR0PBAQDAgP4MB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBgBgNVHREEWTBXgg5mdHAuZm9v
YmFyLmNvbYIPbWFpbC5mb29iYXIuY29tgRJzdXBwb3J0QGZvb2Jhci5jb22gIAYK
KwYBBAGCNxQCA6ASDBBhZG1pbkBmb29iYXIuY29tMBwGA1UdEgQVMBOCEWlzc3Vl
ci5mb29iYXIuY29tMDIGA1UdHwQrMCkwJ6AloCOGIWZvb2JhLmNvbS9kaXN0cmli
dXRpb24vcG9pbnQuaHRtbDArBggrBgEFBQcBAQQfMB0wGwYIKwYBBQUHMAGBD2lu
Zm9AZm9vYmFyLmNvbTARBglghkgBhvhCAQEEBAMCBeAwDQYJKoZIhvcNAQELBQAD
ggEBACo98o1sBOTwHgljhrLTSmx6EUnmZjgGyAJJz62dgVyMT2+l2f8d/BLORBKg
xtqXj9oPwmlFfd19M5py2mCWPs+MwONkcUV++Y7p6HiyvlQQAhkUywHf6WnK27Z4
afd2jrzjJFEZj5GoIH0piFT5vWsTXHDKYfRdzr9FU6L38BemIs4FbGLSd43KEizj
5vzC6ccHKcmOkLHCV+GTGX7FA8NmWajBeQIYE06aEWwJgPAVXsHuB5cfDyR95Z/w
7BYGItkG8DRj0BIIdbpKxhPa4vZScXiNydT6pph9FEtzFcGgw4KwjZfxVsvvpGTe
VeTIr1P7uVWABgJ7i+DkbVriKKk=
-----END CERTIFICATE-----";

        #endregion

        [TestMethod]
        public void ChainMethodsRejectUntrustedSelfSignedCertificate()
        {
            using X509Certificate2 cert = CreateCertificate();

            Assert.IsTrue(cert.IsSelfSigned());
            Assert.IsFalse(cert.BuildChain());
            Assert.IsFalse(cert.IsValidCertificate());
            Assert.Throws<CryptographicException>(() => cert.BuildIssuerChain());
            Assert.Throws<CryptographicException>(() => cert.BuildIssuerChainPem());
        }

        [TestMethod]
        public void CertificateFromPem()
        {
            using X509Certificate2 cert = Certificate.CreateFromPem(CertPem);
            AssertCertificateProperties(cert);

            using X509Certificate2 certWithKeyPem = Certificate.CreateFromPem(CertKeyPem);
            AssertCertificateProperties(certWithKeyPem);
            Assert.IsFalse(certWithKeyPem.HasPrivateKey);
        }

        [TestMethod]
        [DataRow("not a PEM certificate")]
        [DataRow(Certificate.PemCertFooter)]
        [DataRow(Certificate.PemCertHeader + "AQID")]
        [DataRow(Certificate.PemCertFooter + Certificate.PemCertHeader)]
        [DataRow(Certificate.PemCertHeader + "not base64!" + Certificate.PemCertFooter)]
        public void CertificateFromPemRejectsMalformedInput(string pem)
        {
            Assert.ThrowsExactly<FormatException>(() => Certificate.CreateFromPem(pem));
        }

        [TestMethod]
        public void CertificateFromPemRejectsNullAndEmptyInput()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => Certificate.CreateFromPem(null!));
            Assert.ThrowsExactly<ArgumentException>(() => Certificate.CreateFromPem(string.Empty));
        }

        [TestMethod]
        public void CertificateFromPemRejectsNonCertificateData()
        {
            string pem = Certificate.PemCertHeader + "\nAQID\n" + Certificate.PemCertFooter;

            Assert.Throws<CryptographicException>(() => Certificate.CreateFromPem(pem));
        }

        [TestMethod]
        public void CertificatePemRoundTrip()
        {
            using X509Certificate2 original = CreateCertificate();
            using X509Certificate2 imported = Certificate.CreateFromPem("\n" + original.ExportPem() + "\n");

            CollectionAssert.AreEqual(original.RawData, imported.RawData);
            Assert.IsFalse(imported.HasPrivateKey);
        }

        [TestMethod]
        public void SubjectAltNameGettersPreserveValuesAndOrder()
        {
            SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("first.example.test");
            san.AddEmailAddress("first@example.test");
            san.AddUserPrincipalName("last,first@example.test");
            san.AddIpAddress(IPAddress.Loopback);
            san.AddDnsName("second.example.test");
            san.AddUri(new Uri("https://example.test/path"));
            san.AddEmailAddress("second@example.test");
            san.AddUserPrincipalName("\u7528\u6237@example.test");
            san.AddDnsName("first.example.test");
            san.AddUserPrincipalName("normal@example.test");
            using X509Certificate2 cert = CreateCertificate(san.Build());

            CollectionAssert.AreEqual(
                new[] { "first.example.test", "second.example.test", "first.example.test" }, cert.GetDnsName());
            CollectionAssert.AreEqual(
                new[] { "first@example.test", "second@example.test" }, cert.GetUserEmailAddress());
            CollectionAssert.AreEqual(
                new[] { "last,first@example.test", "\u7528\u6237@example.test", "normal@example.test" }, cert.GetUserPrincipalName());
        }

        [TestMethod]
        public void SubjectAltNameGettersIgnoreOtherNameWithUnrelatedOid()
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            Asn1Tag otherNameTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
            using (writer.PushSequence())
            {
                foreach (string oid in new[] { "1.2.3.4", "1.3.6.1.4.1.311.20.2.3" })
                {
                    using (writer.PushSequence(otherNameTag))
                    {
                        writer.WriteObjectIdentifier(oid);
                        using (writer.PushSequence(otherNameTag))
                        {
                            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "user@example.test");
                        }
                    }
                }
            }

            using X509Certificate2 cert = CreateCertificate(new X509Extension("2.5.29.17", writer.Encode(), false));

            CollectionAssert.AreEqual(new[] { "user@example.test" }, cert.GetUserPrincipalName());
            Assert.IsEmpty(cert.GetDnsName());
            Assert.IsEmpty(cert.GetUserEmailAddress());
        }

        [TestMethod]
        public void SubjectAltNameGettersReturnEmptyWhenExtensionIsMissing()
        {
            using X509Certificate2 cert = CreateCertificate();

            Assert.IsNull(cert.GetSubjectAltName());
            AssertSubjectAltNamesAreEmpty(cert);
        }

        [TestMethod]
        [DataRow("300282")]
        [DataRow("3003820261")]
        [DataRow("3000FF")]
        public void SubjectAltNameGettersReturnEmptyWhenExtensionIsMalformed(string encodedSan)
        {
            using X509Certificate2 cert = CreateCertificate(
                new X509Extension("2.5.29.17", Convert.FromHexString(encodedSan), false));

            AssertSubjectAltNamesAreEmpty(cert);
        }

        [TestMethod]
        public void SubjectAltNameGettersDiscardPartialResultsWhenExtensionIsMalformed()
        {
            SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("first.example.test");
            san.AddEmailAddress("user@example.test");
            san.AddUserPrincipalName("normal@example.test");
            byte[] encoded = san.Build().RawData;
            // The short sequence contains valid entries followed by a truncated DNS name.
            byte[] malformed = [0x30, (byte)(encoded[1] + 3), .. encoded[2..], 0x82, 0x02, 0x61];
            using X509Certificate2 cert = CreateCertificate(new X509Extension("2.5.29.17", malformed, false));

            AssertSubjectAltNamesAreEmpty(cert);
        }

        [TestMethod]
        public void PrivateKeyPemRoundTripKeepsCertificateKeyUsable()
        {
            using X509Certificate2 cert = CreateCertificate();
            string pem = cert.ExportPrivateKeyPem();

            StringAssert.StartsWith(pem, Certificate.PemRsaKeyHeader);
            StringAssert.EndsWith(pem, Certificate.PemRsaKeyFooter);
            using RSA imported = RSA.Create();
            imported.ImportFromPem(pem);
            byte[] data = [1, 2, 3, 4];
            byte[] signature = imported.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using RSA publicKey = cert.GetRSAPublicKey()!;
            Assert.IsTrue(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

            Assert.AreEqual(pem, cert.ExportPrivateKeyPem());
            using RSA privateKey = cert.GetRSAPrivateKey()!;
            byte[] secondSignature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.IsTrue(publicKey.VerifyData(data, secondSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        [TestMethod]
        public void PrivateKeyPemRejectsCertificateWithoutPrivateKey()
        {
            using X509Certificate2 cert = Certificate.CreateFromPem(CertPem);

            Assert.ThrowsExactly<InvalidOperationException>(() => cert.ExportPrivateKeyPem());
        }

        [TestMethod]
        public void PrivateKeyPemRejectsNonRsaCertificate()
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            CertificateRequest request = new CertificateRequest("CN=ECDSA test", key, HashAlgorithmName.SHA256);
            using X509Certificate2 cert = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

            Assert.ThrowsExactly<InvalidOperationException>(() => cert.ExportPrivateKeyPem());
        }

        [TestMethod]
        [DataRow(-1, 1, false)]
        [DataRow(-2, -1, true)]
        [DataRow(1, 2, true)]
        public void IsExpiredChecksCertificateValidityPeriod(int notBeforeDays, int notAfterDays, bool expected)
        {
            using X509Certificate2 cert = CreateCertificate(notBeforeDays: notBeforeDays, notAfterDays: notAfterDays);

            Assert.AreEqual(expected, cert.IsExpired());
        }

        private static X509Certificate2 CreateCertificate(X509Extension? extension = null, int notBeforeDays = -1, int notAfterDays = 1)
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new CertificateRequest(
                $"CN=Gearbox test {Guid.NewGuid():N}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (extension != null)
            {
                request.CertificateExtensions.Add(extension);
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            return request.CreateSelfSigned(now.AddDays(notBeforeDays), now.AddDays(notAfterDays));
        }

        private static void AssertSubjectAltNamesAreEmpty(X509Certificate2 cert)
        {
            Assert.IsEmpty(cert.GetDnsName());
            Assert.IsEmpty(cert.GetUserEmailAddress());
            Assert.IsEmpty(cert.GetUserPrincipalName());
        }

        private static void AssertCertificateProperties(X509Certificate2 cert)
        {
            // Check known values of the test certificate
            Assert.IsNotNull(cert);
            Assert.AreEqual(3, cert.Version);
            Assert.AreEqual("E=engineering@foobar.com, CN=www.foobar.com, OU=Engineering, O=Foobar, L=Issaquah, S=WA, C=US", cert.Issuer);
            Assert.AreEqual("E=engineering@foobar.com, CN=www.foobar.com, OU=Engineering, O=Foobar, L=Issaquah, S=WA, C=US", cert.Subject);
            Assert.AreEqual("55E2692AADE0F4CF", cert.SerialNumber);
            Assert.AreEqual("4628123F4FC174C695BC1D7AF4ED889388AA46A2", cert.Thumbprint);

            List<string> upn = cert.GetUserPrincipalName();
            Assert.IsTrue(upn is ["admin@foobar.com"]);

            List<string> dns = cert.GetDnsName();
            Assert.IsTrue(dns.Count == 2);
            Assert.AreEqual("ftp.foobar.com", dns[0]);
            Assert.AreEqual("mail.foobar.com", dns[1]);

            List<string> email = cert.GetUserEmailAddress();
            Assert.IsTrue(email is ["support@foobar.com"]);

            Assert.AreEqual("DNS Name=ftp.foobar.com, DNS Name=mail.foobar.com, RFC822 Name=support@foobar.com, Other Name:Principal Name=admin@foobar.com", cert.GetSubjectAltName());

            Assert.IsTrue(cert.HasClientAuthenticationUsage());
            Assert.IsTrue(cert.HasServerAuthenticationUsage());
            Assert.IsTrue(cert.IsSelfSigned());

            Assert.IsFalse(cert.IsExpired());
            Assert.IsTrue(cert.IsSelfSigned());
            Assert.IsFalse(cert.BuildChain());
            Assert.Throws<CryptographicException>(cert.BuildIssuerChain);
            Assert.Throws<CryptographicException>(cert.BuildIssuerChainPem);
        }
    }
}
