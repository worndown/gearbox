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
        public void GetBytes_ExplicitSalt_ReturnsSameKeyOnRepeatedDerivation(string password, byte[] salt, int iterations, int keyLength)
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
        public void GetBytes_GeneratedSalt_ReproducesKeyUsingSameSalt(string password, int saltLen, int iterations, int keyLength)
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
        public void GetBytes_SequentialChunks_MatchesSingleRequest(string password, byte[] salt, int iterations)
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
        public void Reset_AfterFullBlocks_RestartsKeySequence(string password, int saltLen, int iterations)
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
        public void Constructor_ShortSaltLength_ThrowsArgumentOutOfRangeException()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new PBKDF2("secret", 7));
        }

        /// <summary>
        /// Tests that exception is thrown when provided salt is not big enough.
        /// </summary>
        [TestMethod]
        public void Constructor_ShortSaltArray_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new PBKDF2("secret", new byte[] { 1, 2, 3, 4, 5, 6, 7 }));
        }

        /// <summary>
        /// Tests that exception is thrown when null salt value is provided.
        /// </summary>
        [TestMethod]
        public void Constructor_NullSalt_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new PBKDF2("secret", null!));
        }

        /// <summary>
        /// Tests that exception is thrown when null password value is provided.
        /// </summary>
        [TestMethod]
        public void Constructor_NullStringPassword_ThrowsArgumentNullException()
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
        public void GetBytes_StringPassword_MatchesBclReference(string password, byte[] salt, int iterations, int keyLength)
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

        [TestMethod]
        [DataRow(0, 1)]
        [DataRow(1, 63)]
        [DataRow(128, 64)]
        [DataRow(129, 65)]
        [DataRow(256, 129)]
        public void GetBytes_BinaryPassword_MatchesBclReference(int passwordLength, int keyLength)
        {
            byte[] password = Enumerable.Range(0, passwordLength).Select(i => (byte)i).ToArray();
            byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2(password, salt, 3, HashAlgorithmName.SHA512, keyLength);
            using PBKDF2 pbkdf2 = new PBKDF2(password, salt, 3, null, CancellationToken.None);

            CollectionAssert.AreEqual(expected, pbkdf2.GetBytes(keyLength));
        }

        [TestMethod]
        public void GetBytes_UnicodeAndEmbeddedNullPassword_MatchesBclReference()
        {
            string password = "päss\0密碼🔑" + new string('x', 200);
            byte[] salt = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 101, HashAlgorithmName.SHA512, 129);

            CollectionAssert.AreEqual(expected, DeriveKey(password, salt, 101, 129));
        }

        [TestMethod]
        public void GetBytes_IrregularChunks_MatchesBclReference()
        {
            int[] lengths = { 1, 2, 61, 64, 65, 3, 128, 7 };
            byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2("password", salt, 2, HashAlgorithmName.SHA512, lengths.Sum());
            using PBKDF2 pbkdf2 = new PBKDF2("password", salt, 2, null, CancellationToken.None);
            List<byte> actual = new List<byte>();

            foreach (int length in lengths)
            {
                actual.AddRange(pbkdf2.GetBytes(length));
            }

            CollectionAssert.AreEqual(expected, actual.ToArray());
        }

        [TestMethod]
        public void Reset_AfterPartialBlock_RestartsBclSequence()
        {
            byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2("password", salt, 2, HashAlgorithmName.SHA512, 129);
            using PBKDF2 pbkdf2 = new PBKDF2("password", salt, 2, null, CancellationToken.None);
            pbkdf2.GetBytes(7);
            pbkdf2.GetBytes(65);
            pbkdf2.Reset();

            CollectionAssert.AreEqual(expected, pbkdf2.GetBytes(expected.Length));
        }

        [TestMethod]
        public void Constructor_CallerPasswordAndSalt_CopiesInputsAndReturnsSaltCopy()
        {
            byte[] password = Encoding.UTF8.GetBytes("password");
            byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] originalSalt = (byte[])salt.Clone();
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2(password, salt, 2, HashAlgorithmName.SHA512, 32);
            using PBKDF2 pbkdf2 = new PBKDF2(password, salt, 2, null, CancellationToken.None);
            Array.Fill(password, (byte)255);
            Array.Fill(salt, (byte)255);
            byte[] exposedSalt = pbkdf2.Salt;
            Array.Fill(exposedSalt, (byte)255);

            CollectionAssert.AreEqual(originalSalt, pbkdf2.Salt);
            CollectionAssert.AreEqual(expected, pbkdf2.GetBytes(32));
            pbkdf2.Dispose();
            pbkdf2.Dispose();
            CollectionAssert.AreEqual(Enumerable.Repeat((byte)255, salt.Length).ToArray(), salt);
            CollectionAssert.AreEqual(Enumerable.Repeat((byte)255, password.Length).ToArray(), password);
        }

        [TestMethod]
        public void Constructor_DefaultOptions_UsesSameIterationsAndRandomSalt()
        {
            using PBKDF2 first = new PBKDF2("password");
            using PBKDF2 second = new PBKDF2("password", 16);
            using PBKDF2 explicitSalt = new PBKDF2("password", second.Salt);
            using PBKDF2 binaryPassword = new PBKDF2(Encoding.UTF8.GetBytes("password"), second.Salt);

            Assert.HasCount(PBKDF2.MinSaltSize, first.Salt);
            Assert.HasCount(16, second.Salt);
            Assert.IsFalse(first.Salt.SequenceEqual(second.Salt[..PBKDF2.MinSaltSize]));
            Assert.AreEqual(210000, first.IterationCount);
            Assert.AreEqual(first.IterationCount, second.IterationCount);
            Assert.AreEqual(first.IterationCount, explicitSalt.IterationCount);
            Assert.AreEqual(first.IterationCount, binaryPassword.IterationCount);
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2("password", second.Salt, second.IterationCount, HashAlgorithmName.SHA512, 32);
            CollectionAssert.AreEqual(expected, binaryPassword.GetBytes(32));
        }

        [TestMethod]
        [DataRow(-1)]
        [DataRow(0)]
        [DataRow(100000001)]
        [DataRow(int.MaxValue)]
        public void Constructor_InvalidIterations_Throws(int iterations)
        {
            ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => new PBKDF2("password", new byte[8], iterations, null, CancellationToken.None));

            Assert.AreEqual("iterations", exception.ParamName);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(7)]
        [DataRow(65)]
        public void Constructor_InvalidSaltLength_Throws(int length)
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new PBKDF2("password", new byte[length]));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new PBKDF2("password", length));
        }

        [TestMethod]
        public void Constructor_NullBytePassword_Throws()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new PBKDF2((byte[])null!, new byte[8]));
        }

        [TestMethod]
        [DataRow(-1)]
        [DataRow(0)]
        [DataRow(int.MaxValue)]
        public void GetBytes_InvalidLength_ThrowsWithoutAdvancingSequence(int length)
        {
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], 2, null, CancellationToken.None);
            ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => pbkdf2.GetBytes(length));

            Assert.AreEqual("cb", exception.ParamName);
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2("password", new byte[8], 2, HashAlgorithmName.SHA512, 32);
            CollectionAssert.AreEqual(expected, pbkdf2.GetBytes(32));
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(2)]
        [DataRow(99)]
        [DataRow(100)]
        [DataRow(101)]
        [DataRow(200)]
        [DataRow(1000)]
        public void GetBytes_Progress_IsMonotonicAndEndsAt100(int iterations)
        {
            List<int> reports = new List<int>();
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], iterations, new InlineProgress(reports.Add), CancellationToken.None);
            pbkdf2.GetBytes(32);

            Assert.AreEqual(0, reports[0]);
            Assert.AreEqual(100, reports[^1]);
            Assert.IsTrue(reports.All(value => value is >= 0 and <= 100));
            CollectionAssert.AreEqual(reports.Order().ToArray(), reports.ToArray());
        }

        [TestMethod]
        public void GetBytes_PreCanceledTokenWithMultipleIterations_ThrowsOperationCanceledException()
        {
            CancellationToken token = new CancellationToken(true);
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], 2, null, token);

            OperationCanceledException exception = Assert.ThrowsExactly<OperationCanceledException>(() => pbkdf2.GetBytes(32));
            Assert.AreEqual(token, exception.CancellationToken);
        }

        [TestMethod]
        public void GetBytes_CancelDuringDerivation_ThrowsBeforeCompletion()
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            List<int> reports = new List<int>();
            InlineProgress progress = new InlineProgress(value =>
            {
                reports.Add(value);
                if (value == 50)
                {
                    cancellation.Cancel();
                }
            });
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], 1000, progress, cancellation.Token);

            OperationCanceledException exception = Assert.ThrowsExactly<OperationCanceledException>(() => pbkdf2.GetBytes(32));

            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.AreEqual(50, reports[^1]);
            Assert.IsFalse(reports.Contains(100));
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(100)]
        public void GetBytes_OneIterationCanceledFromProgressCallback_ThrowsOperationCanceledException(int cancelAt)
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            InlineProgress progress = new InlineProgress(value =>
            {
                if (value == cancelAt)
                {
                    cancellation.Cancel();
                }
            });
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], 1, progress, cancellation.Token);

            OperationCanceledException exception = Assert.ThrowsExactly<OperationCanceledException>(() => pbkdf2.GetBytes(32));

            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
        }

        [TestMethod]
        public void GetBytes_Progress_ReportsEachBlockWithoutDuplicatePercentages()
        {
            List<int> reports = new List<int>();
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], 199, new InlineProgress(reports.Add), CancellationToken.None);
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2("password", new byte[8], 199, HashAlgorithmName.SHA512, 129);

            CollectionAssert.AreEqual(expected, pbkdf2.GetBytes(129));

            int blocks = 0;
            int previous = 100;
            foreach (int percent in reports)
            {
                if (percent == 0)
                {
                    Assert.AreEqual(100, previous);
                    previous = -1;
                    blocks++;
                }

                Assert.IsTrue(percent > previous && percent <= 100);
                previous = percent;
            }

            Assert.AreEqual(3, blocks);
            Assert.AreEqual(100, previous);
        }

        [TestMethod]
        public void GetBytes_ProgressCallbackThrows_ResetRestartsDerivation()
        {
            InvalidOperationException failure = new InvalidOperationException("Progress callback failed.");
            int startedBlocks = 0;
            bool fail = true;
            InlineProgress progress = new InlineProgress(value =>
            {
                if (value == 0 && ++startedBlocks == 2 && fail)
                {
                    throw failure;
                }
            });
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], 2, progress, CancellationToken.None);

            Assert.AreSame(failure, Assert.ThrowsExactly<InvalidOperationException>(() => pbkdf2.GetBytes(129)));
            fail = false;
            pbkdf2.Reset();
            byte[] expected = Rfc2898DeriveBytes.Pbkdf2("password", new byte[8], 2, HashAlgorithmName.SHA512, 129);

            CollectionAssert.AreEqual(expected, pbkdf2.GetBytes(129));
        }

        [TestMethod]
        public void Constructor_InvalidParameters_PreservesCallerPassword()
        {
            byte[] password = Encoding.UTF8.GetBytes("password");
            byte[] original = (byte[])password.Clone();

            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new PBKDF2(password, new byte[8], 0, null, CancellationToken.None));

            CollectionAssert.AreEqual(original, password);
        }

        [TestMethod]
        public void GetBytes_DisposedWithBufferedBytes_ThrowsObjectDisposedException()
        {
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], 2, null, CancellationToken.None);
            pbkdf2.GetBytes(1);
            pbkdf2.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => pbkdf2.GetBytes(32));
        }

        [TestMethod]
        public void Reset_DisposedInstance_ThrowsObjectDisposedException()
        {
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], 2, null, CancellationToken.None);
            pbkdf2.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(pbkdf2.Reset);
        }

        [TestMethod]
        public void GetBytes_PreCanceledTokenWithOneIteration_ThrowsOperationCanceledException()
        {
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], 1, null, new CancellationToken(true));

            Assert.ThrowsExactly<OperationCanceledException>(() => pbkdf2.GetBytes(32));
        }

        [TestMethod]
        public void GetBytes_CanceledTokenWithBufferedBytes_ThrowsOperationCanceledException()
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], 2, null, cancellation.Token);
            pbkdf2.GetBytes(32);
            cancellation.Cancel();

            Assert.ThrowsExactly<OperationCanceledException>(() => pbkdf2.GetBytes(16));
        }

        [TestMethod]
        [DataRow(199)]
        [DataRow(299)]
        public void GetBytes_ProgressPercentages_StayWithinRange(int iterations)
        {
            List<int> reports = new List<int>();
            using PBKDF2 pbkdf2 = new PBKDF2("password", new byte[8], iterations, new InlineProgress(reports.Add), CancellationToken.None);
            pbkdf2.GetBytes(32);

            Assert.IsTrue(reports.All(value => value is >= 0 and <= 100), $"Maximum reported progress was {reports.Max()}%.");
            Assert.AreEqual(100, reports[^1]);
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
