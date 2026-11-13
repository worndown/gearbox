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

        [TestMethod]
        [DataRow("", 1)]
        [DataRow("päss\0密碼🔑", 2)]
        [DataRow("password", 199)]
        public void CreateCipher_MatchesBclKeyDerivation(string password, int iterations)
        {
            byte[] salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
            using Cipher cipher = PBES2.CreateCipher(password, salt, iterations, null, CancellationToken.None);

            AssertBclCanDecrypt(cipher, password, salt, iterations);
        }

        [TestMethod]
        [DataRow("", 1)]
        [DataRow("päss\0密碼🔑", 2)]
        [DataRow("password", 199)]
        public async Task CreateCipherAsync_MatchesBclKeyDerivation(string password, int iterations)
        {
            byte[] salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
            using Cipher cipher = await PBES2.CreateCipherAsync(password, salt, iterations, null, CancellationToken.None);

            AssertBclCanDecrypt(cipher, password, salt, iterations);
        }

        [TestMethod]
        [DataRow(true)]
        [DataRow(false)]
        public async Task CreateCipherAsync_CustomDerivation_InteroperatesWithBclPath(bool reportProgress)
        {
            string password = "päss\0密碼🔑" + new string('x', 200);
            byte[] salt = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
            List<int> reports = new List<int>();
            IProgress<int>? progress = reportProgress ? new InlineProgress(reports.Add) : null;
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            CancellationToken token = reportProgress ? CancellationToken.None : cancellation.Token;
            using Cipher custom = await PBES2.CreateCipherAsync(password, salt, 199, progress, token);
            using Cipher bcl = PBES2.CreateCipher(password, salt, 199, null, CancellationToken.None);

            AssertBclCanDecrypt(custom, password, salt, 199);
            byte[] plainText = { 1, 2, 3 };
            CollectionAssert.AreEqual(plainText, bcl.Decrypt(custom.Encrypt(plainText)));
            CollectionAssert.AreEqual(plainText, custom.Decrypt(bcl.Encrypt(plainText)));

            if (reportProgress)
            {
                Assert.AreEqual(0, reports[0]);
                Assert.AreEqual(100, reports[^1]);
                Assert.IsTrue(reports.Count <= 101);
            }
            else
            {
                Assert.HasCount(0, reports);
            }
        }

        [TestMethod]
        public void CreateCipher_InvalidInputs_Throw()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => PBES2.CreateCipher(null!, new byte[8], 1, null, CancellationToken.None));
            Assert.ThrowsExactly<ArgumentNullException>(() => PBES2.CreateCipher("password", null!, 1, null, CancellationToken.None));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => PBES2.CreateCipher("password", new byte[7], 1, null, CancellationToken.None));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => PBES2.CreateCipher("password", new byte[65], 1, null, CancellationToken.None));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => PBES2.CreateCipher("password", new byte[8], 0, null, CancellationToken.None));
        }

        [TestMethod]
        public async Task CreateCipherAsync_InvalidInputs_Throw()
        {
            await Assert.ThrowsExactlyAsync<ArgumentNullException>(() => PBES2.CreateCipherAsync(null!, new byte[8], 1, null, CancellationToken.None));
            await Assert.ThrowsExactlyAsync<ArgumentNullException>(() => PBES2.CreateCipherAsync("password", null!, 1, null, CancellationToken.None));
            await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(() => PBES2.CreateCipherAsync("password", new byte[7], 1, null, CancellationToken.None));
            await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(() => PBES2.CreateCipherAsync("password", new byte[8], 0, null, CancellationToken.None));
        }

        [TestMethod]
        public async Task CreateCipherAsync_PreCanceledToken_MultipleIterations_CancelsTask()
        {
            CancellationToken token = new CancellationToken(true);
            Task<Cipher> task = PBES2.CreateCipherAsync("password", new byte[8], 2, null, token);

            OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => task);

            Assert.AreEqual(token, exception.CancellationToken);
            Assert.IsTrue(task.IsCanceled);
        }

        [TestMethod]
        public async Task CreateCipherAsync_CancelDuringDerivation_CancelsTask()
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            InlineProgress progress = new InlineProgress(value =>
            {
                if (value == 50)
                {
                    cancellation.Cancel();
                }
            });
            Task<Cipher> task = PBES2.CreateCipherAsync("password", new byte[8], 1000, progress, cancellation.Token);

            OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => task);

            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.IsTrue(task.IsCanceled);
        }

        [TestMethod]
        public void CreateCipher_PreCanceledToken_OneIteration_Throws()
        {
            Assert.ThrowsExactly<OperationCanceledException>(() =>
            {
                using Cipher cipher = PBES2.CreateCipher("password", new byte[8], 1, null, new CancellationToken(true));
            });
        }

        [TestMethod]
        public async Task CreateCipherAsync_PreCanceledToken_OneIteration_Throws()
        {
            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            {
                using Cipher cipher = await PBES2.CreateCipherAsync("password", new byte[8], 1, null, new CancellationToken(true));
            });
        }

        private static void AssertBclCanDecrypt(Cipher cipher, string password, byte[] salt, int iterations)
        {
            byte[] key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA512, 32);
            byte[] plainText = Encoding.UTF8.GetBytes("plaintext\0密碼");
            byte[] associatedData = { 1, 2, 3 };
            byte[] blob = cipher.Encrypt(plainText, associatedData);
            byte[] actual = new byte[plainText.Length];
            using AesGcm aes = new AesGcm(key, 16);
            aes.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(28), blob.AsSpan(12, 16), actual, associatedData);

            Assert.AreEqual(256, cipher.KeySize);
            CollectionAssert.AreEqual(plainText, actual);
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
