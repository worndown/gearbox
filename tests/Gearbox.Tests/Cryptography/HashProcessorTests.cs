using System.Security.Cryptography;
using System.Text;
using Gearbox.Cryptography;

namespace Gearbox.Tests.Cryptography
{
    [TestClass]
    public class HashProcessorTests
    {
        private static readonly string[] Algorithms = ["MD5", "SHA1", "SHA256", "SHA384", "SHA512"];

        public static IEnumerable<object[]> IncrementalHashCases
        {
            get
            {
                int[] lengths = [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 4097];
                foreach (string algorithm in Algorithms)
                {
                    foreach (int length in lengths)
                    {
                        yield return [algorithm, length, false];
                        yield return [algorithm, length, true];
                    }
                }
            }
        }

        [TestMethod]
        [DataRow("MD5", "MD5")]
        [DataRow("md5", "MD5")]
        [DataRow("mD5", "MD5")]
        [DataRow("SHA1", "SHA1")]
        [DataRow("sha1", "SHA1")]
        [DataRow("sHa1", "SHA1")]
        [DataRow("SHA256", "SHA256")]
        [DataRow("sha256", "SHA256")]
        [DataRow("sHa256", "SHA256")]
        [DataRow("SHA384", "SHA384")]
        [DataRow("sha384", "SHA384")]
        [DataRow("sHa384", "SHA384")]
        [DataRow("SHA512", "SHA512")]
        [DataRow("sha512", "SHA512")]
        [DataRow("sHa512", "SHA512")]
        public void Create_SupportedNames_ReturnsCanonicalAlgorithm(string name, string expectedName)
        {
            using HashProcessor fromString = HashProcessor.Create(name);
            using HashProcessor fromName = HashProcessor.Create(new HashAlgorithmName(name));

            Assert.AreEqual(expectedName, fromString.AlgorithmName);
            Assert.AreEqual(expectedName, fromName.AlgorithmName);
            Assert.AreEqual(0L, fromString.BytesProcessed);
            Assert.AreEqual(0L, fromName.BytesProcessed);
            Assert.AreEqual(expectedName, fromString.ProcessFinalBlock(ReadOnlySpan<byte>.Empty).Name);
            Assert.AreEqual(expectedName, fromName.ProcessFinalBlock(ReadOnlySpan<byte>.Empty).Name);
        }

        [TestMethod]
        public void Create_NullOrDefaultName_ThrowsArgumentNullException()
        {
            ArgumentNullException stringException = Assert.ThrowsExactly<ArgumentNullException>(
                () => HashProcessor.Create((string)null!));
            ArgumentNullException nameException = Assert.ThrowsExactly<ArgumentNullException>(
                () => HashProcessor.Create(default(HashAlgorithmName)));

            Assert.AreEqual("algName", stringException.ParamName);
            Assert.AreEqual("algName", nameException.ParamName);
        }

        [TestMethod]
        public void Create_EmptyName_ThrowsArgumentException()
        {
            ArgumentException stringException = Assert.ThrowsExactly<ArgumentException>(
                () => HashProcessor.Create(string.Empty));
            ArgumentException nameException = Assert.ThrowsExactly<ArgumentException>(
                () => HashProcessor.Create(new HashAlgorithmName(string.Empty)));

            Assert.AreEqual("algName", stringException.ParamName);
            Assert.AreEqual("algName", nameException.ParamName);
        }

        [TestMethod]
        [DataRow("invalid")]
        [DataRow(" ")]
        [DataRow("SHA-256")]
        [DataRow(" SHA256")]
        [DataRow("SHA256 ")]
        [DataRow("SHA3-256")]
        public void Create_UnsupportedAlgorithm_ThrowsArgumentException(string name)
        {
            ArgumentException stringException = Assert.ThrowsExactly<ArgumentException>(
                () => HashProcessor.Create(name));
            ArgumentException nameException = Assert.ThrowsExactly<ArgumentException>(
                () => HashProcessor.Create(new HashAlgorithmName(name)));

            Assert.AreEqual("algName", stringException.ParamName);
            Assert.AreEqual("algName", nameException.ParamName);
        }

        [TestMethod]
        [DataRow("MD5")]
        [DataRow("SHA1")]
        [DataRow("SHA256")]
        [DataRow("SHA384")]
        [DataRow("SHA512")]
        public void Create_MultipleProcessors_KeepsHashesIndependent(string algorithm)
        {
            using HashProcessor first = HashProcessor.Create(algorithm);
            using HashProcessor second = HashProcessor.Create(new HashAlgorithmName(algorithm));
            first.ProcessBlock("ab"u8);
            second.ProcessBlock("de"u8);

            Hash secondHash = second.ProcessFinalBlock("f"u8);
            second.Dispose();
            Hash firstHash = first.ProcessFinalBlock("c"u8);

            CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, "abc"u8), firstHash.Value);
            CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, "def"u8), secondHash.Value);
            Assert.AreEqual(3L, first.BytesProcessed);
            Assert.AreEqual(3L, second.BytesProcessed);
        }

        [TestMethod]
        [DataRow("MD5", "36B728E56A99ED647BF988F3A3C6AEB8")]
        [DataRow("SHA1", "23C4DB6A5B362E96519F22A66987D019018DD06D")]
        [DataRow("SHA256", "66163CDAAAAD4FA4F7F5E385778D100965F3C2C8653974033BADAC8CAF1958D5")]
        [DataRow("SHA384", "DD484BAE94DD2F52473821ED50E3EBEC6AAE90874F6CFE5F08E1992ECA1311AE2E38B2ACF27DA16D05F4ADA24C84D262")]
        [DataRow("SHA512", "84DB944FC597124A0DB0295E924E7CF0927DD0E67D35EF7E9AAB179717A006721C735620D2CEF02C02830690D9474FDF607643F9E8818B1B8882281B91D30352")]
        public void ProcessFinalBlock_KnownInput_ReturnsExpectedHash(string algorithm, string expected)
        {
            byte[] data = "The quick brown fox jumps over the lazy dog!"u8.ToArray();
            byte[] original = (byte[])data.Clone();
            using HashProcessor arrayProcessor = HashProcessor.Create(algorithm);
            using HashProcessor spanProcessor = HashProcessor.Create(algorithm);

            Hash arrayHash = arrayProcessor.ProcessFinalBlock(data, data.Length);
            Hash spanHash = spanProcessor.ProcessFinalBlock(data.AsSpan());

            Assert.AreEqual(expected, arrayHash.ToString());
            Assert.AreEqual(expected, spanHash.ToString());
            Assert.AreEqual(algorithm, arrayHash.Name);
            Assert.AreEqual(algorithm, spanHash.Name);
            Assert.AreEqual((long)data.Length, arrayProcessor.BytesProcessed);
            Assert.AreEqual((long)data.Length, spanProcessor.BytesProcessed);
            CollectionAssert.AreEqual(original, data);
        }

        [TestMethod]
        [DataRow("MD5")]
        [DataRow("SHA1")]
        [DataRow("SHA256")]
        [DataRow("SHA384")]
        [DataRow("SHA512")]
        public void ProcessFinalBlock_EmptyInput_ReturnsEmptyMessageHash(string algorithm)
        {
            using HashProcessor arrayProcessor = HashProcessor.Create(algorithm);
            using HashProcessor spanProcessor = HashProcessor.Create(algorithm);
            arrayProcessor.ProcessBlock(Array.Empty<byte>(), 0);
            spanProcessor.ProcessBlock(ReadOnlySpan<byte>.Empty);

            Hash arrayHash = arrayProcessor.ProcessFinalBlock(Array.Empty<byte>(), 0);
            Hash spanHash = spanProcessor.ProcessFinalBlock(ReadOnlySpan<byte>.Empty);
            byte[] expected = ComputeReferenceHash(algorithm, ReadOnlySpan<byte>.Empty);

            CollectionAssert.AreEqual(expected, arrayHash.Value);
            CollectionAssert.AreEqual(expected, spanHash.Value);
            Assert.AreEqual(0L, arrayProcessor.BytesProcessed);
            Assert.AreEqual(0L, spanProcessor.BytesProcessed);
        }

        [TestMethod]
        [DynamicData(nameof(IncrementalHashCases))]
        public void ProcessBlock_IrregularChunks_MatchesBclHash(string algorithm, int length, bool hasFinalData)
        {
            byte[] data = Enumerable.Range(0, length).Select(i => (byte)(i * 17 + 3)).ToArray();
            byte[] original = (byte[])data.Clone();
            int[] chunkSizes = [1, 7, 31, 64, 129];
            int finalLength = hasFinalData ? Math.Min(7, length) : 0;
            int blockLength = length - finalLength;
            int offset = 0;
            int chunkIndex = 0;
            using HashProcessor processor = HashProcessor.Create(algorithm);

            while (offset < blockLength)
            {
                int chunkLength = Math.Min(chunkSizes[chunkIndex % chunkSizes.Length], blockLength - offset);
                if (chunkIndex % 2 == 0)
                {
                    processor.ProcessBlock(data.AsSpan(offset, chunkLength));
                }
                else
                {
                    byte[] buffer = new byte[chunkLength + 3];
                    data.AsSpan(offset, chunkLength).CopyTo(buffer);
                    buffer[^1] = 255;
                    byte[] originalBuffer = (byte[])buffer.Clone();
                    processor.ProcessBlock(buffer, chunkLength);
                    CollectionAssert.AreEqual(originalBuffer, buffer);
                }

                offset += chunkLength;
                chunkIndex++;
                Assert.AreEqual((long)offset, processor.BytesProcessed);
                processor.ProcessBlock(Array.Empty<byte>(), 0);
                processor.ProcessBlock(ReadOnlySpan<byte>.Empty);
                Assert.AreEqual((long)offset, processor.BytesProcessed);
            }

            Hash hash = hasFinalData
                ? processor.ProcessFinalBlock(data.AsSpan(offset))
                : processor.ProcessFinalBlock(Array.Empty<byte>(), 0);

            CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, data), hash.Value);
            Assert.AreEqual(algorithm, hash.Name);
            Assert.AreEqual((long)length, processor.BytesProcessed);
            CollectionAssert.AreEqual(original, data);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(3)]
        [DataRow(8)]
        public void ProcessBlocks_ArrayPrefixes_HashOnlyRequestedBytes(int length)
        {
            byte[] first = [1, 2, 3, 4, 5, 6, 7, 8];
            byte[] final = [11, 12, 13, 14, 15, 16, 17, 18];
            byte[] originalFirst = (byte[])first.Clone();
            byte[] originalFinal = (byte[])final.Clone();
            byte[] expectedData = first[..length].Concat(final[..length]).ToArray();
            using HashProcessor processor = HashProcessor.Create("SHA256");

            processor.ProcessBlock(first, length);
            Assert.AreEqual((long)length, processor.BytesProcessed);
            Hash hash = processor.ProcessFinalBlock(final, length);

            CollectionAssert.AreEqual(SHA256.HashData(expectedData), hash.Value);
            Assert.AreEqual(2L * length, processor.BytesProcessed);
            CollectionAssert.AreEqual(originalFirst, first);
            CollectionAssert.AreEqual(originalFinal, final);
        }

        [TestMethod]
        [DataRow("MD5")]
        [DataRow("SHA1")]
        [DataRow("SHA256")]
        [DataRow("SHA384")]
        [DataRow("SHA512")]
        public void ProcessBlocks_StackAllocatedSlices_HashOnlySelectedBytes(string algorithm)
        {
            Span<byte> buffer = stackalloc byte[] { 255, 1, 2, 3, 4, 5, 255 };
            byte[] original = buffer.ToArray();
            using HashProcessor processor = HashProcessor.Create(algorithm);

            processor.ProcessBlock(buffer.Slice(1, 3));
            Assert.AreEqual(3L, processor.BytesProcessed);
            Hash hash = processor.ProcessFinalBlock(buffer.Slice(4, 2));

            CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, new byte[] { 1, 2, 3, 4, 5 }), hash.Value);
            Assert.AreEqual(5L, processor.BytesProcessed);
            CollectionAssert.AreEqual(original, buffer.ToArray());
        }

        [TestMethod]
        public void ProcessBlock_NullData_ThrowsWithoutChangingHash()
        {
            AssertRejectedInputPreservesHash<ArgumentNullException>(p => p.ProcessBlock(null!, 0), "data");
        }

        [TestMethod]
        public void ProcessFinalBlock_NullData_ThrowsWithoutChangingHash()
        {
            AssertRejectedInputPreservesHash<ArgumentNullException>(p => p.ProcessFinalBlock(null!, 0), "data");
        }

        [TestMethod]
        [DataRow(-1)]
        [DataRow(4)]
        [DataRow(int.MaxValue)]
        public void ProcessBlock_InvalidLength_ThrowsWithoutChangingHash(int length)
        {
            AssertRejectedInputPreservesHash<ArgumentOutOfRangeException>(
                p => p.ProcessBlock(new byte[] { 1, 2, 3 }, length), "length");
        }

        [TestMethod]
        [DataRow(-1)]
        [DataRow(4)]
        [DataRow(int.MaxValue)]
        public void ProcessFinalBlock_InvalidLength_ThrowsWithoutChangingHash(int length)
        {
            AssertRejectedInputPreservesHash<ArgumentOutOfRangeException>(
                p => p.ProcessFinalBlock(new byte[] { 1, 2, 3 }, length), "length");
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void Processing_FinalizedProcessor_ThrowsInvalidOperationException(bool emptyHash)
        {
            byte[] data = emptyHash ? Array.Empty<byte>() : new byte[] { 1, 2, 3 };
            using HashProcessor processor = HashProcessor.Create("SHA256");
            Hash hash = processor.ProcessFinalBlock(data, data.Length);
            byte[] expected = SHA256.HashData(data);

            Assert.ThrowsExactly<InvalidOperationException>(() => processor.ProcessBlock(data, data.Length));
            Assert.ThrowsExactly<InvalidOperationException>(() => processor.ProcessBlock(data.AsSpan()));
            Assert.ThrowsExactly<InvalidOperationException>(() => processor.ProcessBlock(ReadOnlySpan<byte>.Empty));
            Assert.ThrowsExactly<InvalidOperationException>(() => processor.ProcessFinalBlock(data, data.Length));
            Assert.ThrowsExactly<InvalidOperationException>(() => processor.ProcessFinalBlock(data.AsSpan()));
            Assert.ThrowsExactly<InvalidOperationException>(() => processor.ProcessFinalBlock(ReadOnlySpan<byte>.Empty));
            Assert.ThrowsExactly<InvalidOperationException>(() => processor.ProcessBlock(null!, -1));
            Assert.ThrowsExactly<InvalidOperationException>(() => processor.ProcessFinalBlock(null!, -1));
            Assert.AreEqual((long)data.Length, processor.BytesProcessed);
            CollectionAssert.AreEqual(expected, hash.Value);
        }

        [TestMethod]
        [DataRow("MD5")]
        [DataRow("SHA1")]
        [DataRow("SHA256")]
        [DataRow("SHA384")]
        [DataRow("SHA512")]
        public void Reset_NewProcessor_PreservesEmptyHashState(string algorithm)
        {
            using HashProcessor processor = HashProcessor.Create(algorithm);
            processor.Reset();
            processor.Reset();

            Assert.AreEqual(0L, processor.BytesProcessed);
            Assert.AreEqual(algorithm, processor.AlgorithmName);
            Hash hash = processor.ProcessFinalBlock(ReadOnlySpan<byte>.Empty);
            CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, ReadOnlySpan<byte>.Empty), hash.Value);
        }

        [TestMethod]
        [DataRow("MD5")]
        [DataRow("SHA1")]
        [DataRow("SHA256")]
        [DataRow("SHA384")]
        [DataRow("SHA512")]
        public void Reset_PartialHash_DiscardsDataAndRestartsCount(string algorithm)
        {
            byte[] pending = Enumerable.Range(0, 257).Select(i => (byte)i).ToArray();
            using HashProcessor processor = HashProcessor.Create(algorithm);
            processor.ProcessBlock(pending.AsSpan(0, 63));
            processor.ProcessBlock(pending[63..], pending.Length - 63);
            Assert.AreEqual((long)pending.Length, processor.BytesProcessed);

            processor.Reset();
            Assert.AreEqual(0L, processor.BytesProcessed);
            processor.ProcessBlock("ab"u8);
            Assert.AreEqual(2L, processor.BytesProcessed);
            Hash hash = processor.ProcessFinalBlock("c"u8);

            CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, "abc"u8), hash.Value);
            Assert.AreEqual(3L, processor.BytesProcessed);
        }

        [TestMethod]
        [DataRow("MD5")]
        [DataRow("SHA1")]
        [DataRow("SHA256")]
        [DataRow("SHA384")]
        [DataRow("SHA512")]
        public void Reset_FinalizedProcessor_PermitsReuseAndPreservesReturnedHash(string algorithm)
        {
            byte[] firstData = "first"u8.ToArray();
            using HashProcessor processor = HashProcessor.Create(algorithm);
            Hash firstHash = processor.ProcessFinalBlock(firstData, firstData.Length);
            byte[] firstExpected = ComputeReferenceHash(algorithm, firstData);
            Array.Fill(firstData, (byte)255);
            Assert.AreEqual(5L, processor.BytesProcessed);

            processor.Reset();
            Assert.AreEqual(0L, processor.BytesProcessed);
            processor.ProcessBlock("se"u8);
            Hash secondHash = processor.ProcessFinalBlock("cond"u8);
            byte[] secondExpected = ComputeReferenceHash(algorithm, "second"u8);
            Assert.AreEqual(6L, processor.BytesProcessed);
            Assert.AreNotSame(firstHash.Value, secondHash.Value);
            processor.Dispose();

            CollectionAssert.AreEqual(firstExpected, firstHash.Value);
            CollectionAssert.AreEqual(secondExpected, secondHash.Value);
            Assert.AreEqual(algorithm, firstHash.Name);
            Assert.AreEqual(algorithm, secondHash.Name);
            Assert.AreEqual(algorithm, processor.AlgorithmName);
            Assert.AreEqual(6L, processor.BytesProcessed);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(2)]
        public void Dispose_RepeatedCalls_PreservesMetadata(int state)
        {
            using HashProcessor processor = HashProcessor.Create("SHA256");
            if (state > 0)
            {
                processor.ProcessBlock(new byte[] { 1, 2, 3 }, 3);
            }

            if (state == 2)
            {
                processor.ProcessFinalBlock(ReadOnlySpan<byte>.Empty);
            }

            long count = processor.BytesProcessed;
            processor.Dispose();
            processor.Dispose();

            Assert.AreEqual("SHA256", processor.AlgorithmName);
            Assert.AreEqual(count, processor.BytesProcessed);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void Processing_DisposedProcessor_ThrowsObjectDisposedException(bool finalized)
        {
            byte[] data = [1, 2, 3];
            using HashProcessor processor = HashProcessor.Create("SHA256");
            processor.ProcessBlock(data, data.Length);
            if (finalized)
            {
                processor.ProcessFinalBlock(ReadOnlySpan<byte>.Empty);
            }

            processor.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => processor.ProcessBlock(data, data.Length));
            Assert.ThrowsExactly<ObjectDisposedException>(() => processor.ProcessBlock(data.AsSpan()));
            Assert.ThrowsExactly<ObjectDisposedException>(() => processor.ProcessBlock(ReadOnlySpan<byte>.Empty));
            Assert.ThrowsExactly<ObjectDisposedException>(() => processor.ProcessFinalBlock(data, data.Length));
            Assert.ThrowsExactly<ObjectDisposedException>(() => processor.ProcessFinalBlock(data.AsSpan()));
            Assert.ThrowsExactly<ObjectDisposedException>(() => processor.ProcessFinalBlock(ReadOnlySpan<byte>.Empty));
            Assert.ThrowsExactly<ObjectDisposedException>(() => processor.ProcessBlock(null!, -1));
            Assert.ThrowsExactly<ObjectDisposedException>(() => processor.ProcessFinalBlock(null!, -1));
            Assert.AreEqual(3L, processor.BytesProcessed);
        }

        [TestMethod]
        public void Reset_DisposedProcessor_ThrowsObjectDisposedException()
        {
            using HashProcessor processor = HashProcessor.Create("SHA256");
            processor.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => processor.Reset());
            Assert.AreEqual(0L, processor.BytesProcessed);
        }


        public static IEnumerable<object[]> HelperHashCases
        {
            get
            {
                int[] lengths = [0, 1, 65535, 65536, 65537, 131101];
                foreach (string algorithm in Algorithms)
                {
                    foreach (int length in lengths)
                    {
                        yield return [algorithm, length];
                    }
                }
            }
        }

        public static IEnumerable<object[]> StringHashCases
        {
            get
            {
                string[] texts = [string.Empty, "abc", "Café 😀", "a\0b", " \t\r\n", "\uFEFFabc", "\u00E9", "e\u0301"];
                foreach (string algorithm in Algorithms)
                {
                    foreach (string text in texts)
                    {
                        yield return [algorithm, text];
                    }
                }
            }
        }

        [TestMethod]
        [DynamicData(nameof(HelperHashCases))]
        public void ComputeHash_BufferSlice_MatchesBclHash(string algorithm, int length)
        {
            byte[] data = CreateHelperData(length + 5);
            byte[] original = (byte[])data.Clone();

            Hash hash = HashProcessor.ComputeHash(data.AsSpan(2, length), new HashAlgorithmName(algorithm.ToLowerInvariant()));

            CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, data.AsSpan(2, length)), hash.Value);
            Assert.AreEqual(algorithm, hash.Name);
            CollectionAssert.AreEqual(original, data);
        }

        [TestMethod]
        [DynamicData(nameof(StringHashCases))]
        public void ComputeStringHash_DefaultEncoding_PreservesExactUtf8Content(string algorithm, string text)
        {
            Hash hash = HashProcessor.ComputeStringHash(text, new HashAlgorithmName(algorithm.ToLowerInvariant()));

            CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, Encoding.UTF8.GetBytes(text)), hash.Value);
            Assert.AreEqual(algorithm, hash.Name);
        }

        [TestMethod]
        [DataRow("utf-8")]
        [DataRow("utf-16")]
        [DataRow("utf-16BE")]
        [DataRow("utf-32")]
        [DataRow("us-ascii")]
        public void ComputeStringHash_ExplicitEncoding_HashesBytesWithoutPreamble(string encodingName)
        {
            const string text = "Aé😀\0";
            Encoding encoding = Encoding.GetEncoding(encodingName);

            Hash hash = HashProcessor.ComputeStringHash(text, HashAlgorithmName.SHA256, encoding);

            CollectionAssert.AreEqual(SHA256.HashData(encoding.GetBytes(text)), hash.Value);
        }

        [TestMethod]
        public void ComputeStringHash_StrictEncodingWithInvalidSurrogate_ThrowsEncoderFallbackException()
        {
            Assert.ThrowsExactly<EncoderFallbackException>(() =>
                HashProcessor.ComputeStringHash("\uD800", HashAlgorithmName.SHA256, new UTF8Encoding(false, true)));
        }

        [TestMethod]
        [DynamicData(nameof(HelperHashCases))]
        public void ComputeHash_StreamAtCurrentPosition_MatchesBclHashAndLeavesOpen(string algorithm, int length)
        {
            byte[] data = CreateHelperData(length + 7);
            using MemoryStream stream = new MemoryStream(data, writable: false);
            stream.Position = 7;

            Hash hash = HashProcessor.ComputeHash(stream, new HashAlgorithmName(algorithm.ToLowerInvariant()));

            CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, data.AsSpan(7)), hash.Value);
            Assert.AreEqual(algorithm, hash.Name);
            Assert.AreEqual((long)data.Length, stream.Position);
            Assert.IsTrue(stream.CanRead);
        }

        [TestMethod]
        [DynamicData(nameof(HelperHashCases))]
        public async Task ComputeHashAsync_StreamAtCurrentPosition_MatchesBclHashAndLeavesOpen(string algorithm, int length)
        {
            byte[] data = CreateHelperData(length + 7);
            using MemoryStream stream = new MemoryStream(data, writable: false);
            stream.Position = 7;

            Hash hash = await HashProcessor.ComputeHashAsync(stream, new HashAlgorithmName(algorithm.ToLowerInvariant()));

            CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, data.AsSpan(7)), hash.Value);
            Assert.AreEqual(algorithm, hash.Name);
            Assert.AreEqual((long)data.Length, stream.Position);
            Assert.IsTrue(stream.CanRead);
        }

        [TestMethod]
        public void ComputeHash_ShortNonSeekableReads_HashesUntilEof()
        {
            byte[] data = CreateHelperData(131101);
            using ChunkedReadStream stream = new ChunkedReadStream(data);

            Hash hash = HashProcessor.ComputeHash(stream, HashAlgorithmName.SHA256);

            CollectionAssert.AreEqual(SHA256.HashData(data), hash.Value);
            Assert.IsTrue(stream.SyncReadCount > 2);
            Assert.AreEqual(0, stream.AsyncReadCount);
            Assert.IsTrue(stream.MaxRequestedSize <= 65536);
            Assert.IsTrue(stream.CanRead);
        }

        [TestMethod]
        public async Task ComputeHashAsync_ShortNonSeekableReads_UsesAsyncReadsUntilEof()
        {
            byte[] data = CreateHelperData(131101);
            using ChunkedReadStream stream = new ChunkedReadStream(data) { AsyncOnly = true };
            using CancellationTokenSource cancellation = new CancellationTokenSource();

            Hash hash = await HashProcessor.ComputeHashAsync(stream, HashAlgorithmName.SHA256, cancellation.Token);

            CollectionAssert.AreEqual(SHA256.HashData(data), hash.Value);
            Assert.IsTrue(stream.AsyncReadCount > 2);
            Assert.AreEqual(0, stream.SyncReadCount);
            Assert.IsTrue(stream.MaxRequestedSize <= 65536);
            Assert.AreEqual(cancellation.Token, stream.LastCancellationToken);
            Assert.IsTrue(stream.CanRead);
        }

        [TestMethod]
        [DynamicData(nameof(HelperHashCases))]
        public void ComputeFileHash_FileContents_MatchesBclHashAndReleasesFile(string algorithm, int length)
        {
            byte[] data = CreateHelperData(length);
            string path = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(path, data);

                Hash hash = HashProcessor.ComputeFileHash(path, new HashAlgorithmName(algorithm.ToLowerInvariant()));

                CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, data), hash.Value);
                Assert.AreEqual(algorithm, hash.Name);
                using FileStream exclusive = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                Assert.AreEqual((long)length, exclusive.Length);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [TestMethod]
        [DynamicData(nameof(HelperHashCases))]
        public async Task ComputeFileHashAsync_FileContents_MatchesBclHashAndReleasesFile(string algorithm, int length)
        {
            byte[] data = CreateHelperData(length);
            string path = Path.GetTempFileName();
            try
            {
                await File.WriteAllBytesAsync(path, data);

                Hash hash = await HashProcessor.ComputeFileHashAsync(path, new HashAlgorithmName(algorithm.ToLowerInvariant()));

                CollectionAssert.AreEqual(ComputeReferenceHash(algorithm, data), hash.Value);
                Assert.AreEqual(algorithm, hash.Name);
                using FileStream exclusive = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                Assert.AreEqual((long)length, exclusive.Length);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [TestMethod]
        public async Task ComputeHelpers_NullInputs_ThrowArgumentNullException()
        {
            Assert.AreEqual("text", Assert.ThrowsExactly<ArgumentNullException>(() =>
                HashProcessor.ComputeStringHash(null!, HashAlgorithmName.SHA256)).ParamName);
            Assert.AreEqual("stream", Assert.ThrowsExactly<ArgumentNullException>(() =>
                HashProcessor.ComputeHash((Stream)null!, HashAlgorithmName.SHA256)).ParamName);
            Assert.AreEqual("path", Assert.ThrowsExactly<ArgumentNullException>(() =>
                HashProcessor.ComputeFileHash(null!, HashAlgorithmName.SHA256)).ParamName);
            Assert.AreEqual("stream", (await Assert.ThrowsExactlyAsync<ArgumentNullException>(() =>
                HashProcessor.ComputeHashAsync(null!, HashAlgorithmName.SHA256))).ParamName);
            Assert.AreEqual("path", (await Assert.ThrowsExactlyAsync<ArgumentNullException>(() =>
                HashProcessor.ComputeFileHashAsync(null!, HashAlgorithmName.SHA256))).ParamName);
        }

        [TestMethod]
        public async Task ComputeFileHelpers_EmptyPath_ThrowsArgumentException()
        {
            Assert.AreEqual("path", Assert.ThrowsExactly<ArgumentException>(() =>
                HashProcessor.ComputeFileHash(string.Empty, HashAlgorithmName.SHA256)).ParamName);
            Assert.AreEqual("path", (await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
                HashProcessor.ComputeFileHashAsync(string.Empty, HashAlgorithmName.SHA256))).ParamName);
        }

        [TestMethod]
        public async Task ComputeHashHelpers_UnreadableStream_ThrowsArgumentException()
        {
            using MemoryStream stream = new MemoryStream();
            stream.Dispose();

            Assert.AreEqual("stream", Assert.ThrowsExactly<ArgumentException>(() =>
                HashProcessor.ComputeHash(stream, HashAlgorithmName.SHA256)).ParamName);
            Assert.AreEqual("stream", (await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
                HashProcessor.ComputeHashAsync(stream, HashAlgorithmName.SHA256))).ParamName);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("unsupported")]
        public async Task ComputeHelpers_InvalidAlgorithm_ReportsAlgorithmParameter(string? name)
        {
            byte[] data = [1, 2, 3];
            using MemoryStream stream = new MemoryStream(data);
            HashAlgorithmName algorithm = new HashAlgorithmName(name);
            string missingPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".missing");
            Action[] syncCalls =
            [
                () => HashProcessor.ComputeHash(data.AsSpan(), algorithm),
                () => HashProcessor.ComputeStringHash("text", algorithm),
                () => HashProcessor.ComputeHash(stream, algorithm),
                () => HashProcessor.ComputeFileHash(missingPath, algorithm)
            ];
            foreach (Action call in syncCalls)
            {
                ArgumentException exception = name is null
                    ? Assert.ThrowsExactly<ArgumentNullException>(call)
                    : Assert.ThrowsExactly<ArgumentException>(call);
                Assert.AreEqual("algName", exception.ParamName);
            }

            Func<Task>[] asyncCalls =
            [
                () => HashProcessor.ComputeHashAsync(stream, algorithm),
                () => HashProcessor.ComputeFileHashAsync(missingPath, algorithm)
            ];
            foreach (Func<Task> call in asyncCalls)
            {
                ArgumentException exception = name is null
                    ? await Assert.ThrowsExactlyAsync<ArgumentNullException>(call)
                    : await Assert.ThrowsExactlyAsync<ArgumentException>(call);
                Assert.AreEqual("algName", exception.ParamName);
            }

            Assert.AreEqual(0L, stream.Position);
            Assert.IsTrue(stream.CanRead);
        }

        [TestMethod]
        public async Task ComputeFileHelpers_MissingFile_PropagatesFileNotFoundException()
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".missing");

            Assert.AreEqual(path, Assert.ThrowsExactly<FileNotFoundException>(() =>
                HashProcessor.ComputeFileHash(path, HashAlgorithmName.SHA256)).FileName);
            Assert.AreEqual(path, (await Assert.ThrowsExactlyAsync<FileNotFoundException>(() =>
                HashProcessor.ComputeFileHashAsync(path, HashAlgorithmName.SHA256))).FileName);
        }

        [TestMethod]
        public async Task ComputeHashAsync_PreCanceledToken_DoesNotReadOrCloseStream()
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            using ChunkedReadStream stream = new ChunkedReadStream(new byte[] { 1, 2, 3 }) { AsyncOnly = true };

            Task<Hash> task = HashProcessor.ComputeHashAsync(stream, HashAlgorithmName.SHA256, cancellation.Token);
            OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => task);

            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.IsTrue(task.IsCanceled);
            Assert.AreEqual(0, stream.SyncReadCount);
            Assert.AreEqual(0, stream.AsyncReadCount);
            Assert.IsTrue(stream.CanRead);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(131101)]
        public async Task ComputeHashAsync_CancellationDuringRead_CancelsAndLeavesStreamOpen(int length)
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            using ChunkedReadStream stream = new ChunkedReadStream(CreateHelperData(length))
            {
                AsyncOnly = true,
                AfterRead = cancellation.Cancel
            };

            Task<Hash> task = HashProcessor.ComputeHashAsync(stream, HashAlgorithmName.SHA256, cancellation.Token);
            OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => task);

            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.IsTrue(task.IsCanceled);
            Assert.AreEqual(1, stream.AsyncReadCount);
            Assert.AreEqual(0, stream.SyncReadCount);
            Assert.IsTrue(stream.CanRead);
        }

        [TestMethod]
        public async Task ComputeFileHashAsync_PreCanceledToken_DoesNotOpenFile()
        {
            using CancellationTokenSource cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".missing");

            Task<Hash> task = HashProcessor.ComputeFileHashAsync(path, HashAlgorithmName.SHA256, cancellation.Token);
            OperationCanceledException exception = await Assert.ThrowsAsync<OperationCanceledException>(() => task);

            Assert.AreEqual(cancellation.Token, exception.CancellationToken);
            Assert.IsTrue(task.IsCanceled);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task ComputeHashHelpers_ReadFailure_PropagatesAndLeavesStreamOpen(bool useAsync)
        {
            IOException failure = new IOException("Read failed.");
            using ChunkedReadStream stream = new ChunkedReadStream(new byte[] { 1, 2, 3 })
            {
                AsyncOnly = useAsync,
                ReadException = failure
            };

            IOException exception = useAsync
                ? await Assert.ThrowsExactlyAsync<IOException>(() => HashProcessor.ComputeHashAsync(stream, HashAlgorithmName.SHA256))
                : Assert.ThrowsExactly<IOException>(() => HashProcessor.ComputeHash(stream, HashAlgorithmName.SHA256));

            Assert.AreSame(failure, exception);
            Assert.IsTrue(stream.CanRead);
        }

        private static byte[] CreateHelperData(int length)
        {
            return Enumerable.Range(0, length).Select(i => (byte)(i * 17 + 3)).ToArray();
        }

        private sealed class ChunkedReadStream : Stream
        {
            private readonly MemoryStream inner;
            private bool disposed;

            public ChunkedReadStream(byte[] data)
            {
                this.inner = new MemoryStream(data, writable: false);
            }

            public bool AsyncOnly { get; init; }
            public Action? AfterRead { get; init; }
            public Exception? ReadException { get; init; }
            public int SyncReadCount { get; private set; }
            public int AsyncReadCount { get; private set; }
            public int MaxRequestedSize { get; private set; }
            public CancellationToken LastCancellationToken { get; private set; }
            public override bool CanRead => !this.disposed;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                this.SyncReadCount++;
                this.MaxRequestedSize = Math.Max(this.MaxRequestedSize, count);
                if (this.AsyncOnly)
                {
                    throw new InvalidOperationException("Synchronous reads are disabled.");
                }

                return this.ReadChunk(buffer.AsSpan(offset, count));
            }

            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                this.AsyncReadCount++;
                this.MaxRequestedSize = Math.Max(this.MaxRequestedSize, buffer.Length);
                this.LastCancellationToken = cancellationToken;
                await Task.Yield();
                // Returning data even after cancellation exercises the helper's cancellation checks.
                return this.ReadChunk(buffer.Span);
            }

            public override void Flush() => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    this.disposed = true;
                    this.inner.Dispose();
                }

                base.Dispose(disposing);
            }

            private int ReadChunk(Span<byte> buffer)
            {
                if (this.ReadException is not null)
                {
                    throw this.ReadException;
                }

                int length = this.inner.Read(buffer[..Math.Min(buffer.Length, 8191)]);
                this.AfterRead?.Invoke();
                return length;
            }
        }

        private static void AssertRejectedInputPreservesHash<TException>(Action<HashProcessor> action, string parameterName)
            where TException : ArgumentException
        {
            using HashProcessor processor = HashProcessor.Create("SHA256");
            processor.ProcessBlock("prefix"u8);

            TException exception = Assert.ThrowsExactly<TException>(() => action(processor));

            Assert.AreEqual(parameterName, exception.ParamName);
            Assert.AreEqual(6L, processor.BytesProcessed);
            Hash hash = processor.ProcessFinalBlock("suffix"u8);
            CollectionAssert.AreEqual(SHA256.HashData("prefixsuffix"u8), hash.Value);
            Assert.AreEqual(12L, processor.BytesProcessed);
        }

        private static byte[] ComputeReferenceHash(string algorithm, ReadOnlySpan<byte> data)
        {
            return algorithm switch
            {
                "MD5" => MD5.HashData(data),
                "SHA1" => SHA1.HashData(data),
                "SHA256" => SHA256.HashData(data),
                "SHA384" => SHA384.HashData(data),
                "SHA512" => SHA512.HashData(data),
                _ => throw new ArgumentException("Unsupported reference algorithm.", nameof(algorithm))
            };
        }
    }
}
