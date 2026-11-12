using System.Security.Cryptography;
using System.Text;
using Gearbox.Cryptography;

namespace Gearbox.Tests.Cryptography
{
    /// <summary>
    /// PBKDF2 tests.
    /// </summary>
    [TestClass]
    public class PBKDF2Tests
    {
        /// <summary>
        /// Tests key derivation with caller supplied salt.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">Iteration count.</param>
        /// <param name="keyLength">Key length, in bytes, to generate.</param>
        [TestMethod]
        [DataRow("", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 1, 8)]
        [DataRow("p", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 2, 10)]
        [DataRow("test@pass123", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 100, 128)]
        [DataRow("AnotherPa$$word", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }, 100, 222)]
        public void DeriveKey_ExplicitSalt(string password, byte[] salt, int iterations, int keyLength)
        {
            byte[] key1 = DeriveKey(password, salt, iterations, keyLength);
            Assert.IsNotNull(key1);
            Assert.HasCount(keyLength, key1);

            byte[] key2 = DeriveKey(password, salt, iterations, keyLength);
            Assert.IsNotNull(key2);
            Assert.HasCount(keyLength, key2);

            Assert.IsTrue(key1.SequenceEqual(key2));
        }

        /// <summary>
        /// Tests key derivation where new random salt of specified length is generated.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="saltLen">Length, in bytes, of salt to generate.</param>
        /// <param name="iterations">Iteration count.</param>
        /// <param name="keyLength">Key length, in bytes, to generate.</param>
        [TestMethod]
        [DataRow("", 8, 1, 8)]
        [DataRow("p", 8, 2, 10)]
        [DataRow("test@pass123", 16, 100, 128)]
        [DataRow("AnotherPa$$word", 64, 100, 222)]
        public void DeriveKey_RandomSalt(string password, int saltLen, int iterations, int keyLength)
        {
            byte[] key1 = DeriveKey(password, saltLen, iterations, keyLength, out byte[] salt);
            Assert.IsNotNull(key1);
            Assert.HasCount(keyLength, key1);

            byte[] key2 = DeriveKey(password, salt, iterations, keyLength);
            Assert.IsNotNull(key2);
            Assert.HasCount(keyLength, key2);

            Assert.IsTrue(key1.SequenceEqual(key2));
        }

        /// <summary>
        /// Tests that GetBytes returns the same key sequence when called sequentially.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">Iteration count.</param>
        [TestMethod]
        [DataRow("", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 1)]
        [DataRow("p", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 2)]
        [DataRow("test@pass123", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 100)]
        [DataRow("AnotherPa$$word", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }, 100)]
        public void DeriveKey_Sequential(string password, byte[] salt, int iterations)
        {
            // Desired key size
            const int keySize = 1000;
            const int chunkSize = 100;

            // Create two instances initialized with identical key derivation settings
            using (PBKDF2 pbkdfA = new PBKDF2(password, salt, iterations, null, CancellationToken.None))
            using (PBKDF2 pbkdfB = new PBKDF2(password, salt, iterations, null, CancellationToken.None))
            {
                // Get key bytes from the first instance in a single call
                byte[] keyA = pbkdfA.GetBytes(keySize);
                Assert.HasCount(keySize, keyA);

                // Get key bytes from the second instance, but do that in multiple calls
                byte[] keyB = new byte[keySize];
                for (int i = 0; i < keySize / chunkSize; ++i)
                {
                    byte[] tmp = pbkdfB.GetBytes(chunkSize);
                    Assert.HasCount(chunkSize, tmp);
                    Buffer.BlockCopy(tmp, 0, keyB, i * chunkSize, chunkSize);
                }

                // Both keys should be identical
                Assert.IsTrue(keyA.SequenceEqual(keyB));
            }
        }

        /// <summary>
        /// Tests that reset state works as expected.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="saltLen">Length of salt to use.</param>
        /// <param name="iterations">Iteration count.</param>
        [TestMethod]
        [DataRow("", 8, 1)]
        [DataRow("p", 8, 2)]
        [DataRow("test@pass123", 16, 100)]
        [DataRow("AnotherPa$$word", 64, 100)]
        public void ResetState(string password, int saltLen, int iterations)
        {
            const int blockSize = 64;

            using (PBKDF2 pbkdf2 = new PBKDF2(password, saltLen, iterations, null, CancellationToken.None))
            {
                byte[] keyStart = pbkdf2.GetBytes(blockSize);
                Assert.HasCount(blockSize, keyStart);

                byte[] keyNext = pbkdf2.GetBytes(blockSize);
                Assert.HasCount(blockSize, keyNext);
                Assert.IsFalse(keyStart.SequenceEqual(keyNext));

                // Reset state
                pbkdf2.Reset();
                keyNext = pbkdf2.GetBytes(blockSize);
                Assert.HasCount(blockSize, keyNext);
                Assert.IsTrue(keyStart.SequenceEqual(keyNext));
            }
        }

        /// <summary>
        /// Tests that exception is thrown when small salt length is specified.
        /// </summary>
        [TestMethod]
        public void Salt_SmallLength_ThrowsException()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new PBKDF2("secret", 7));
        }

        /// <summary>
        /// Tests that exception is thrown when provided salt is not big enough.
        /// </summary>
        [TestMethod]
        public void Salt_BadValue_ThrowsException()
        {
            Assert.Throws<ArgumentException>(() => new PBKDF2("secret", new byte[] { 1, 2, 3, 4, 5, 6, 7 }));
        }

        /// <summary>
        /// Tests that exception is thrown when null salt value is provided.
        /// </summary>
        [TestMethod]
        public void Salt_NullValue_ThrowsException()
        {
            Assert.Throws<ArgumentNullException>(() => new PBKDF2("secret", null!));
        }

        /// <summary>
        /// Tests that exception is thrown when null password value is provided.
        /// </summary>
        [TestMethod]
        public void Password_NullValue_ThrowsException()
        {
            Assert.Throws<ArgumentNullException>(() => new PBKDF2(null!, 16));
        }

        /// <summary>
        /// Known-answer test: the hand-rolled PBKDF2 must produce the exact same key as the
        /// platform reference implementation (Rfc2898DeriveBytes.Pbkdf2 with HMAC-SHA512).
        /// This validates correctness independently, not just self-consistency.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">Iteration count.</param>
        /// <param name="keyLength">Key length, in bytes, to generate.</param>
        [TestMethod]
        [DataRow("", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 1, 32)]
        [DataRow("password", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 1000, 64)]
        [DataRow("test@pass123", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, 500, 100)]
        public void DeriveKey_MatchesBclReference(string password, byte[] salt, int iterations, int keyLength)
        {
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                HashAlgorithmName.SHA512,
                keyLength);

            byte[] actual = DeriveKey(password, salt, iterations, keyLength);

            Assert.IsTrue(expected.SequenceEqual(actual));
        }

        /// <summary>
        /// Derives key using specified key derivation settings.
        /// </summary>
        /// <param name="password">Password used in key derivation.</param>
        /// <param name="salt">Salt used in key derivation.</param>
        /// <param name="iterations">Key derivation iteration count.</param>
        /// <param name="length">Requested key length in bytes.</param>
        /// <returns>Derived key of requested length.</returns>
        private static byte[] DeriveKey(string password, byte[] salt, int iterations, int length)
        {
            using (PBKDF2 pbkdf2 = new PBKDF2(password, salt, iterations, null, CancellationToken.None))
            {
                Assert.IsTrue(salt.SequenceEqual(pbkdf2.Salt));
                return pbkdf2.GetBytes(length);
            }
        }

        /// <summary>
        /// Derives key using specified key derivation settings.
        /// </summary>
        /// <param name="password">Password used in key derivation.</param>
        /// <param name="saltSize">Size of random salt to generate.</param>
        /// <param name="iterations">Key derivation iteration count.</param>
        /// <param name="length">Requested key length in bytes.</param>
        /// <param name="salt">Generated salt value that was used in key derivation.</param>
        /// <returns>Derived key of requested length.</returns>
        private static byte[] DeriveKey(string password, int saltSize, int iterations, int length, out byte[] salt)
        {
            using (PBKDF2 pbkdf2 = new PBKDF2(password, saltSize, iterations, null, CancellationToken.None))
            {
                salt = pbkdf2.Salt;
                Assert.HasCount(saltSize, salt);
                return pbkdf2.GetBytes(length);
            }
        }
    }
}
