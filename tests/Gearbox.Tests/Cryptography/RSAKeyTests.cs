using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using Gearbox.Cryptography;

namespace Gearbox.Tests.Cryptography
{
    [TestClass]
    public class RSAKeyTests
    {
        [TestMethod]
        public void EncodeParametersPem_KnownKeys_ReturnsExpectedPem()
        {
            string result = RSAKey.EncodeParametersPem(RSATestKey.RsaKey1024);
            Assert.AreEqual(RSATestKey.RsaKeyPem1024, result);

            result = RSAKey.EncodeParametersPem(RSATestKey.RsaKey2048);
            Assert.AreEqual(RSATestKey.RsaKeyPem2048, result);

            result = RSAKey.EncodeParametersPem(RSATestKey.RsaKey4096);
            Assert.AreEqual(RSATestKey.RsaKeyPem4096, result);

            result = RSAKey.EncodeParametersPem(RSATestKey.RsaKey8192);
            Assert.AreEqual(RSATestKey.RsaKeyPem8192, result);
        }

        [TestMethod]
        public void CreateFullKeyParameters_KnownPrimesAndExponent_DerivesExpectedParameters()
        {
            TestParametersDerivation(RSATestKey.RsaKey1024);
            TestParametersDerivation(RSATestKey.RsaKey2048);
            TestParametersDerivation(RSATestKey.RsaKey4096);
            TestParametersDerivation(RSATestKey.RsaKey8192);
        }

        [TestMethod]
        public void EncodeParametersPem_LeadingZeroPadding_ReturnsCanonicalPemWithoutChangingParameters()
        {
            RSAParameters parameters = RSATestKey.RsaKey1024;
            parameters.Modulus = [0, 0, .. parameters.Modulus!];
            parameters.Exponent = [0, 0, .. parameters.Exponent!];
            parameters.D = [0, 0, .. parameters.D!];
            parameters.P = [0, 0, .. parameters.P!];
            parameters.Q = [0, 0, .. parameters.Q!];
            parameters.DP = [0, 0, .. parameters.DP!];
            parameters.DQ = [0, 0, .. parameters.DQ!];
            parameters.InverseQ = [0, 0, .. parameters.InverseQ!];
            byte[][] arrays = [parameters.Modulus!, parameters.Exponent!, parameters.D!, parameters.P!,
                parameters.Q!, parameters.DP!, parameters.DQ!, parameters.InverseQ!];
            byte[][] originals = arrays.Select(array => array.ToArray()).ToArray();

            string pem = RSAKey.EncodeParametersPem(parameters);

            Assert.AreEqual(RSATestKey.RsaKeyPem1024, pem);
            for (int i = 0; i < arrays.Length; i++)
            {
                CollectionAssert.AreEqual(originals[i], arrays[i]);
            }
        }

        [TestMethod]
        [DataRow(nameof(RSAParameters.Modulus))]
        [DataRow(nameof(RSAParameters.Exponent))]
        [DataRow(nameof(RSAParameters.D))]
        [DataRow(nameof(RSAParameters.P))]
        [DataRow(nameof(RSAParameters.Q))]
        [DataRow(nameof(RSAParameters.DP))]
        [DataRow(nameof(RSAParameters.DQ))]
        [DataRow(nameof(RSAParameters.InverseQ))]
        public void EncodeParametersPem_MissingOrEmptyParameter_ThrowsArgumentException(string fieldName)
        {
            foreach (byte[]? invalid in new byte[]?[] { null, [] })
            {
                object parameters = RSATestKey.RsaKey1024;
                typeof(RSAParameters).GetField(fieldName)!.SetValue(parameters, invalid);

                ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
                    () => RSAKey.EncodeParametersPem((RSAParameters)parameters));

                Assert.AreEqual(fieldName, exception.ParamName);
            }
        }

        [TestMethod]
        public void EncodeParametersPem_SmallKey_ContainsCompleteDerSequence()
        {
            RSAParameters parameters = RSAKey.CreateFullKeyParameters(17, 61, 53);
            AsnReader reader = new AsnReader(DecodePem(RSAKey.EncodeParametersPem(parameters)), AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();

            // The textbook key's version, n, e, d, p, q, DP, DQ, and InverseQ.
            int[] expected = [0, 3233, 17, 2753, 61, 53, 53, 49, 38];
            foreach (int value in expected)
            {
                Assert.AreEqual(new BigInteger(value), sequence.ReadInteger());
            }

            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
        }

        [TestMethod]
        [DataRow(263, nameof(RSAParameters.D))]
        [DataRow(585, nameof(RSAParameters.DP))]
        [DataRow(693, nameof(RSAParameters.DQ))]
        [DataRow(867, nameof(RSAParameters.D))]
        public void CreateFullKeyParameters_ShortPrivateValues_ImportAndPemRoundTrip(int exponent, string paddedField)
        {
            // These exponents produce private values shorter than their required widths
            // with the fixed 1024-bit fixture; 867 also produces redundant ASN.1 input padding.
            BigInteger p = new BigInteger(RSATestKey.RsaKey1024.P, true, true);
            BigInteger q = new BigInteger(RSATestKey.RsaKey1024.Q, true, true);
            RSAParameters parameters = RSAKey.CreateFullKeyParameters(exponent, p, q);
            Assert.AreEqual(128, parameters.D!.Length);
            foreach (byte[] value in new[] { parameters.P!, parameters.Q!, parameters.DP!, parameters.DQ!, parameters.InverseQ! })
            {
                Assert.AreEqual(64, value.Length);
            }

            byte[] padded = (byte[])typeof(RSAParameters).GetField(paddedField)!.GetValue(parameters)!;
            Assert.AreEqual((byte)0, padded[0]);
            using RSA key = RSA.Create();
            key.ImportParameters(parameters);
            // ExportParameters includes the provider's fixed-width padding.
            string pem = RSAKey.EncodeParametersPem(key.ExportParameters(true));
            CollectionAssert.AreEqual(key.ExportRSAPrivateKey(), DecodePem(pem));

            using RSA imported = RSA.Create();
            imported.ImportFromPem(pem);
            byte[] data = [1, 2, 3, 4];
            byte[] signature = imported.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.IsTrue(key.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        [TestMethod]
        public void CreateFullKeyParameters_UnequalPrimeByteLengths_PadsPrimeAndInverseQ()
        {
            RSAParameters parameters = RSAKey.CreateFullKeyParameters(17, 61, 65521);

            Assert.AreEqual(3, parameters.Modulus!.Length);
            Assert.AreEqual(3, parameters.D!.Length);
            CollectionAssert.AreEqual(new byte[] { 0, 61 }, parameters.P);
            CollectionAssert.AreEqual(new byte[] { 0, 35 }, parameters.InverseQ);
            Assert.AreEqual(2, parameters.Q!.Length);
            Assert.AreEqual(2, parameters.DP!.Length);
            Assert.AreEqual(2, parameters.DQ!.Length);
        }

        [TestMethod]
        public void CreateFullKeyParameters_MatchingModulus_MatchesThreeArgumentOverload()
        {
            BigInteger exponent = new BigInteger(RSATestKey.RsaKey1024.Exponent, true, true);
            BigInteger p = new BigInteger(RSATestKey.RsaKey1024.P, true, true);
            BigInteger q = new BigInteger(RSATestKey.RsaKey1024.Q, true, true);
            BigInteger modulus = new BigInteger(RSATestKey.RsaKey1024.Modulus, true, true);

            RSAParameters parameters = RSAKey.CreateFullKeyParameters(exponent, p, q, modulus);

            CompareRsaParameters(RSAKey.CreateFullKeyParameters(exponent, p, q), parameters);
        }

        [TestMethod]
        public void CreateFullKeyParameters_MismatchedModulus_ThrowsArgumentException()
        {
            ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
                () => RSAKey.CreateFullKeyParameters(17, 61, 53, 3234));

            Assert.AreEqual("modulus", exception.ParamName);
        }

        [TestMethod]
        [DataRow(-1)]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(4)]
        [DataRow(3233)]
        [DataRow(3235)]
        public void CreateFullKeyParameters_InvalidExponent_ThrowsArgumentOutOfRangeException(int exponent)
        {
            ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => RSAKey.CreateFullKeyParameters(exponent, 61, 53));

            Assert.AreEqual("exponent", exception.ParamName);
        }

        [TestMethod]
        [DataRow(-3)]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(4)]
        public void CreateFullKeyParameters_InvalidPrime_ThrowsArgumentOutOfRangeException(int prime)
        {
            ArgumentOutOfRangeException pException = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => RSAKey.CreateFullKeyParameters(17, prime, 53));
            ArgumentOutOfRangeException qException = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => RSAKey.CreateFullKeyParameters(17, 61, prime));

            Assert.AreEqual("p", pException.ParamName);
            Assert.AreEqual("q", qException.ParamName);
        }

        [TestMethod]
        [DataRow(3, 61, 53, "exponent")]
        [DataRow(17, 61, 61, "q")]
        [DataRow(5, 9, 15, "q")]
        [DataRow(17, 3, 16777213, "q")]
        [DataRow(17, 16777213, 3, "p")]
        public void CreateFullKeyParameters_InvalidKeyRelationship_ThrowsArgumentException(int exponent, int p, int q, string parameterName)
        {
            ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
                () => RSAKey.CreateFullKeyParameters(exponent, p, q));

            Assert.AreEqual(parameterName, exception.ParamName);
        }

        private static byte[] DecodePem(string pem)
        {
            PemFields fields = PemEncoding.Find(pem);
            return Convert.FromBase64String(pem[fields.Base64Data]);
        }

        private static void TestParametersDerivation(RSAParameters parameters)
        {
            BigInteger exponent = new BigInteger(parameters.Exponent, true, true);
            BigInteger p = new BigInteger(parameters.P, true, true);
            BigInteger q = new BigInteger(parameters.Q, true, true);

            RSAParameters result = RSAKey.CreateFullKeyParameters(exponent, p, q);
            CompareRsaParameters(parameters, result);
        }

        private static void CompareRsaParameters(RSAParameters expected, RSAParameters actual)
        {
            Assert.IsTrue(actual.Modulus.SequenceEqual(expected.Modulus));
            Assert.IsTrue(actual.Exponent.SequenceEqual(expected.Exponent));
            Assert.IsTrue(actual.P.SequenceEqual(expected.P));
            Assert.IsTrue(actual.Q.SequenceEqual(expected.Q));
            Assert.IsTrue(actual.DP.SequenceEqual(expected.DP));
            Assert.IsTrue(actual.DQ.SequenceEqual(expected.DQ));
            Assert.IsTrue(actual.D.SequenceEqual(expected.D));
            Assert.IsTrue(actual.InverseQ.SequenceEqual(expected.InverseQ));
        }
    }
}
