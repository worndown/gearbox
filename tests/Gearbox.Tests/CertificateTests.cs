using System.Security.Cryptography;
using Gearbox.Extensions;

namespace Gearbox.Tests
{
    using System.Security.Cryptography.X509Certificates;

    [TestClass]
    public class CertificateTest
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
        public void ChainTest()
        {
            string thumb = "213fe6fb6f6c849a0e14c572052ef7f8bb1bd347";

            X509Certificate2? cert = Certificate.FindByThumbprint(thumb, StoreName.My, StoreLocation.CurrentUser);
            if (cert != null)
            {
                ICollection<X509Certificate2> chain = cert.BuildIssuerChain();
            }
        }

        [TestMethod]
        public void CertificateFromPem()
        {
            X509Certificate2 cert = Certificate.CreateFromPem(CertPem);
            AssertCertificateProperties(cert);

            cert = Certificate.CreateFromPem(CertKeyPem);
            AssertCertificateProperties(cert);
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