using System.Security.Cryptography;
using System.Text;
using Gearbox.Cryptography;

namespace Gearbox.Tests.Cryptography
{
    [TestClass]
    public class PBES2Tests
    {
        /// <summary>
        /// Tests that data encrypted with a derived cipher round-trips through a cipher
        /// derived again from the same password, salt and iterations.
        /// </summary>
        [TestMethod]
        public void KeyDerivation()
        {
            string password = GetRandomPassword();
            int iterations = GetRandomIterationCount();
            byte[] salt = GetRandomSalt();
            byte[] plainText = GetRandomData();

            // Derive key and encrypt plain text
            byte[] cipherText = DeriveKeyAndEncrypt(password, iterations, salt, plainText);
            Assert.IsFalse(plainText.SequenceEqual(cipherText));

            // Derive key again and decrypt cipher text
            byte[] decrypted = DeriveKeyAndDecrypt(password, iterations, salt, cipherText);
            Assert.IsTrue(plainText.SequenceEqual(decrypted));
        }

        /// <summary>
        /// Tests that encrypting identical plaintext twice yields different ciphertext,
        /// proving a fresh random nonce is used per call.
        /// </summary>
        [TestMethod]
        public void Encryption_IsNonDeterministic()
        {
            string password = GetRandomPassword();
            int iterations = GetRandomIterationCount();
            byte[] salt = GetRandomSalt();
            byte[] plainText = GetRandomData();

            using (Cipher cipher = PBES2.CreateCipher(password, salt, iterations, null, CancellationToken.None))
            {
                byte[] blob1 = cipher.Encrypt(plainText);
                byte[] blob2 = cipher.Encrypt(plainText);

                // Fresh nonce per call => different ciphertext for identical plaintext.
                Assert.IsFalse(blob1.SequenceEqual(blob2));

                // Both still decrypt back to the original.
                Assert.IsTrue(plainText.SequenceEqual(cipher.Decrypt(blob1)));
                Assert.IsTrue(plainText.SequenceEqual(cipher.Decrypt(blob2)));
            }
        }

        /// <summary>
        /// Tests that two cipher instances created from identical key derivation settings
        /// interoperate: one can decrypt data encrypted by the other.
        /// </summary>
        [TestMethod]
        public void Cipher_SameSettings_Interoperate()
        {
            string password = GetRandomPassword();
            int iterations = GetRandomIterationCount();
            byte[] salt = GetRandomSalt();
            byte[] plainText = GetRandomData();

            using (Cipher cipher1 = PBES2.CreateCipher(password, salt, iterations, null, CancellationToken.None))
            using (Cipher cipher2 = PBES2.CreateCipher(password, salt, iterations, null, CancellationToken.None))
            {
                byte[] blob = cipher1.Encrypt(plainText);
                byte[] result = cipher2.Decrypt(blob);
                Assert.IsTrue(plainText.SequenceEqual(result));
            }
        }

        /// <summary>
        /// Tests that tampering with the encrypted blob is detected (authentication fails).
        /// </summary>
        [TestMethod]
        public void Decrypt_TamperedData_Throws()
        {
            string password = GetRandomPassword();
            int iterations = GetRandomIterationCount();
            byte[] salt = GetRandomSalt();
            byte[] plainText = GetRandomData();

            using (Cipher cipher = PBES2.CreateCipher(password, salt, iterations, null, CancellationToken.None))
            {
                byte[] blob = cipher.Encrypt(plainText);
                blob[^1] ^= 0xFF; // flip a bit in the ciphertext/tag

                Assert.Throws<CryptographicException>(() => cipher.Decrypt(blob));
            }
        }

        /// <summary>
        /// Tests that decrypting with a cipher derived from the wrong password fails authentication.
        /// </summary>
        [TestMethod]
        public void Decrypt_WrongPassword_Throws()
        {
            int iterations = GetRandomIterationCount();
            byte[] salt = GetRandomSalt();
            byte[] plainText = GetRandomData();
            byte[] blob;

            using (Cipher cipher = PBES2.CreateCipher("correct horse", salt, iterations, null, CancellationToken.None))
            {
                blob = cipher.Encrypt(plainText);
            }

            using (Cipher wrong = PBES2.CreateCipher("battery staple", salt, iterations, null, CancellationToken.None))
            {
                Assert.Throws<CryptographicException>(() => wrong.Decrypt(blob));
            }
        }

        /// <summary>
        /// Tests that associated data binds the ciphertext: decrypting with different AAD fails authentication.
        /// </summary>
        [TestMethod]
        public void Decrypt_WrongAssociatedData_Throws()
        {
            string password = GetRandomPassword();
            int iterations = GetRandomIterationCount();
            byte[] salt = GetRandomSalt();
            byte[] plainText = GetRandomData();
            byte[] aad = { 1, 2, 3 };
            byte[] otherAad = { 1, 2, 4 };

            using (Cipher cipher = PBES2.CreateCipher(password, salt, iterations, null, CancellationToken.None))
            {
                byte[] blob = cipher.Encrypt(plainText, aad);

                // Same AAD round-trips.
                Assert.IsTrue(plainText.SequenceEqual(cipher.Decrypt(blob, aad)));

                // Different AAD fails authentication.
                Assert.Throws<CryptographicException>(() => cipher.Decrypt(blob, otherAad));
            }
        }

        /// <summary>
        /// Derives key using specified settings and encrypts data.
        /// </summary>
        /// <param name="password">Password used to derive key.</param>
        /// <param name="iterations">Number of iterations during key derivation.</param>
        /// <param name="salt">Salt used in key derivation.</param>
        /// <param name="plainText">Data to encrypt.</param>
        /// <returns>Buffer with cipher text.</returns>
        private static byte[] DeriveKeyAndEncrypt(string password, int iterations, byte[] salt, byte[] plainText)
        {
            using (Cipher cipher = PBES2.CreateCipher(password, salt, iterations, null, CancellationToken.None))
            {
                Assert.AreEqual(256, cipher.KeySize);
                return cipher.Encrypt(plainText);
            }
        }

        /// <summary>
        /// Derives key using specified settings and decrypts data.
        /// </summary>
        /// <param name="password">Password used to derive key.</param>
        /// <param name="iterations">Number of key derivation iterations.</param>
        /// <param name="salt">Salt used to derive key.</param>
        /// <param name="cipherText">Cipher text to decrypt.</param>
        /// <returns>Buffer with plain text.</returns>
        private static byte[] DeriveKeyAndDecrypt(string password, int iterations, byte[] salt, byte[] cipherText)
        {
            using (Cipher cipher = PBES2.CreateCipher(password, salt, iterations, null, CancellationToken.None))
            {
                return cipher.Decrypt(cipherText);
            }
        }

        /// <summary>
        /// Returns random iteration count for testing.
        /// </summary>
        /// <returns>Random iteration count.</returns>
        private static int GetRandomIterationCount()
        {
            return RandomNumberGenerator.GetInt32(100, 500);
        }

        /// <summary>
        /// Returns random salt value.
        /// </summary>
        /// <returns>Random salt value.</returns>
        private static byte[] GetRandomSalt()
        {
            int length = RandomNumberGenerator.GetInt32(8, 65);
            return RandomNumberGenerator.GetBytes(length);
        }

        /// <summary>
        /// Returns buffer of random size with random data.
        /// </summary>
        /// <returns>Buffer with random data.</returns>
        private static byte[] GetRandomData()
        {
            int length = RandomNumberGenerator.GetInt32(1, 4096);
            return RandomNumberGenerator.GetBytes(length);
        }

        /// <summary>
        /// Returns random password string.
        /// </summary>
        /// <returns>String with random password.</returns>
        private static string GetRandomPassword()
        {
            int len = RandomNumberGenerator.GetInt32(1, 64);
            StringBuilder sb = new StringBuilder(len);
            for (int i = 0; i < len; ++i)
            {
                sb.Append(Convert.ToChar(RandomNumberGenerator.GetInt32(65, 127)));
            }

            return sb.ToString();
        }
    }
}
