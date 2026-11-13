using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Gearbox.Cryptography
{
    /// <summary>
    /// Incrementally computes MD5, SHA1, SHA256, SHA384 or SHA512 hashes.
    /// </summary>
    /// <remarks>
    /// Call <see cref="Reset"/> before processing another hash after finalization.
    /// Instances are not thread-safe.
    /// </remarks>
    public class HashProcessor : IDisposable
    {
        private const int StreamBufferSize = 64 * 1024;

        private static readonly Dictionary<string, HashAlgorithmName> HashAlgorithms =
            new Dictionary<string, HashAlgorithmName>(StringComparer.OrdinalIgnoreCase)
            {
                { "MD5", HashAlgorithmName.MD5 },
                { "SHA1", HashAlgorithmName.SHA1 },
                { "SHA256", HashAlgorithmName.SHA256 },
                { "SHA384", HashAlgorithmName.SHA384 },
                { "SHA512", HashAlgorithmName.SHA512 }
            };

        private readonly HashAlgorithmName algorithmName;
        private readonly IncrementalHash algorithm;
        private bool finalized;
        private bool disposed;

        /// <summary>
        /// Initializes a new instance of the HashProcessor class.
        /// </summary>
        /// <param name="algorithmName">Hash algorithm name.</param>
        private HashProcessor(HashAlgorithmName algorithmName)
        {
            this.algorithmName = algorithmName;
            this.algorithm = IncrementalHash.CreateHash(algorithmName);
        }

        /// <summary>
        /// Canonical hash algorithm name. Remains readable after disposal.
        /// </summary>
        public string AlgorithmName => this.algorithmName.Name!;

        /// <summary>
        /// Total bytes hashed since creation or the last reset, including the final block.
        /// </summary>
        /// <remarks>The completed count remains readable after finalization and disposal.</remarks>
        public long BytesProcessed { get; private set; }

        /// <summary>
        /// Disposes this object.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Performs object disposal.
        /// </summary>
        /// <param name="disposing">Whether object is being disposed.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing && !this.disposed)
            {
                this.disposed = true;
                this.algorithm.Dispose();
            }
        }

        /// <summary>
        /// Hashes the first <paramref name="length"/> bytes of the supplied array.
        /// </summary>
        /// <param name="data">Data to hash.</param>
        /// <param name="length">Number of bytes to hash. May be zero.</param>
        /// <exception cref="ObjectDisposedException">The processor has been disposed.</exception>
        /// <exception cref="InvalidOperationException">The hash has been finalized. Call Reset before processing more data.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="data"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="length"/> is negative or exceeds the array length.</exception>
        public void ProcessBlock(byte[] data, int length)
        {
            this.ThrowIfUnavailable();
            this.AppendData(ValidateData(data, length));
        }

        /// <summary>
        /// Hashes a block of data without copying it. Empty blocks are valid.
        /// </summary>
        /// <param name="data">Data to hash.</param>
        /// <exception cref="ObjectDisposedException">The processor has been disposed.</exception>
        /// <exception cref="InvalidOperationException">The hash has been finalized. Call Reset before processing more data.</exception>
        public void ProcessBlock(ReadOnlySpan<byte> data)
        {
            this.ThrowIfUnavailable();
            this.AppendData(data);
        }

        /// <summary>
        /// Hashes the first <paramref name="length"/> bytes of the supplied array and finalizes the hash.
        /// </summary>
        /// <param name="data">Data to hash.</param>
        /// <param name="length">Number of bytes to hash. May be zero to finalize previously processed data.</param>
        /// <returns>Resulting hash.</returns>
        /// <exception cref="ObjectDisposedException">The processor has been disposed.</exception>
        /// <exception cref="InvalidOperationException">The hash has already been finalized. Call Reset before processing more data.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="data"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="length"/> is negative or exceeds the array length.</exception>
        public Hash ProcessFinalBlock(byte[] data, int length)
        {
            this.ThrowIfUnavailable();
            return this.FinalizeHash(ValidateData(data, length));
        }

        /// <summary>
        /// Hashes a final block without copying it and returns the completed hash.
        /// </summary>
        /// <param name="data">Final data to hash. May be empty to finalize previously processed data.</param>
        /// <returns>Resulting hash, or the empty-message hash if no data has been processed.</returns>
        /// <exception cref="ObjectDisposedException">The processor has been disposed.</exception>
        /// <exception cref="InvalidOperationException">The hash has already been finalized. Call Reset before processing more data.</exception>
        public Hash ProcessFinalBlock(ReadOnlySpan<byte> data)
        {
            this.ThrowIfUnavailable();
            return this.FinalizeHash(data);
        }

        /// <summary>
        /// Discards any pending hash and resets the byte count, permitting another hash to be processed.
        /// </summary>
        /// <exception cref="ObjectDisposedException">The processor has been disposed.</exception>
        public void Reset()
        {
            ObjectDisposedException.ThrowIf(this.disposed, this);
            this.algorithm.GetHashAndReset(stackalloc byte[this.algorithm.HashLengthInBytes]);
            this.BytesProcessed = 0;
            this.finalized = false;
        }

        /// <summary>
        /// Creates hash processor.
        /// </summary>
        /// <param name="algName">MD5, SHA1, SHA256, SHA384 or SHA512, matched case-insensitively.</param>
        /// <returns>Hash processor instance.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="algName"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="algName"/> is empty or unsupported.</exception>
        public static HashProcessor Create(string algName)
        {
            ArgumentException.ThrowIfNullOrEmpty(algName);

            if (!HashAlgorithms.TryGetValue(algName, out HashAlgorithmName algorithmName))
            {
                throw new ArgumentException($"Unsupported hash algorithm: '{algName}'.", nameof(algName));
            }

            return new HashProcessor(algorithmName);
        }

        /// <summary>
        /// Creates hash processor.
        /// </summary>
        /// <param name="algName">MD5, SHA1, SHA256, SHA384 or SHA512, matched case-insensitively.</param>
        /// <returns>Hash processor instance.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="algName"/> has a null name.</exception>
        /// <exception cref="ArgumentException"><paramref name="algName"/> has an empty or unsupported name.</exception>
        public static HashProcessor Create(HashAlgorithmName algName)
        {
            ArgumentException.ThrowIfNullOrEmpty(algName.Name, nameof(algName));
            return Create(algName.Name);
        }

        /// <summary>
        /// Computes the hash of a buffer or slice without copying the input.
        /// </summary>
        /// <param name="data">Data to hash. May be empty.</param>
        /// <param name="algName">Supported hash algorithm, matched case-insensitively.</param>
        /// <returns>The hash with its canonical algorithm name.</returns>
        public static Hash ComputeHash(ReadOnlySpan<byte> data, HashAlgorithmName algName)
        {
            using HashProcessor processor = Create(algName);
            return processor.ProcessFinalBlock(data);
        }

        /// <summary>
        /// Computes the hash of a string encoded without an encoding preamble (BOM).
        /// </summary>
        /// <param name="text">Text to hash. May be empty; no normalization or newline conversion is performed.</param>
        /// <param name="algName">Supported hash algorithm, matched case-insensitively.</param>
        /// <param name="encoding">Encoding to use. Defaults to UTF-8.</param>
        /// <returns>The hash with its canonical algorithm name.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="text"/> is null.</exception>
        public static Hash ComputeStringHash(string text, HashAlgorithmName algName, Encoding? encoding = null)
        {
            ArgumentNullException.ThrowIfNull(text);
            using HashProcessor processor = Create(algName);
            return processor.ProcessFinalBlock((encoding ?? Encoding.UTF8).GetBytes(text));
        }

        /// <summary>
        /// Computes the hash of a readable stream from its current position to EOF, leaving it open.
        /// </summary>
        /// <param name="stream">Stream to read. Seeking is not required.</param>
        /// <param name="algName">Supported hash algorithm, matched case-insensitively.</param>
        /// <returns>The hash with its canonical algorithm name.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="stream"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="stream"/> is not readable.</exception>
        public static Hash ComputeHash(Stream stream, HashAlgorithmName algName)
        {
            ValidateStream(stream);
            using HashProcessor processor = Create(algName);
            return ComputeStreamHash(stream, processor);
        }

        /// <summary>
        /// Asynchronously hashes a readable stream from its current position to EOF, leaving it open.
        /// </summary>
        /// <param name="stream">Stream to read. Seeking is not required.</param>
        /// <param name="algName">Supported hash algorithm, matched case-insensitively.</param>
        /// <param name="cancellationToken">Token used to cancel reading and hashing.</param>
        /// <returns>The hash with its canonical algorithm name.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="stream"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="stream"/> is not readable.</exception>
        /// <exception cref="OperationCanceledException">The operation was canceled.</exception>
        public static async Task<Hash> ComputeHashAsync(Stream stream, HashAlgorithmName algName, CancellationToken cancellationToken = default)
        {
            ValidateStream(stream);
            using HashProcessor processor = Create(algName);
            cancellationToken.ThrowIfCancellationRequested();
            return await ComputeStreamHashAsync(stream, processor, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Computes the hash of a file using a bounded buffer, closing the file when finished.
        /// </summary>
        /// <param name="path">Path to the file.</param>
        /// <param name="algName">Supported hash algorithm, matched case-insensitively.</param>
        /// <returns>The hash with its canonical algorithm name.</returns>
        public static Hash ComputeFileHash(string path, HashAlgorithmName algName)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);
            using HashProcessor processor = Create(algName);
            using FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, StreamBufferSize, FileOptions.SequentialScan);
            return ComputeStreamHash(stream, processor);
        }

        /// <summary>
        /// Asynchronously computes a file hash using a bounded buffer, closing the file when finished.
        /// </summary>
        /// <param name="path">Path to the file.</param>
        /// <param name="algName">Supported hash algorithm, matched case-insensitively.</param>
        /// <param name="cancellationToken">Token used to cancel reading and hashing.</param>
        /// <returns>The hash with its canonical algorithm name.</returns>
        /// <exception cref="OperationCanceledException">The operation was canceled.</exception>
        public static async Task<Hash> ComputeFileHashAsync(string path, HashAlgorithmName algName, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);
            using HashProcessor processor = Create(algName);
            cancellationToken.ThrowIfCancellationRequested();
            await using FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, StreamBufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await ComputeStreamHashAsync(stream, processor, cancellationToken).ConfigureAwait(false);
        }

        private static void ValidateStream(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);
            if (!stream.CanRead)
            {
                throw new ArgumentException("Stream must be readable.", nameof(stream));
            }
        }

        private static Hash ComputeStreamHash(Stream stream, HashProcessor processor)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(StreamBufferSize);
            try
            {
                int length;
                while ((length = stream.Read(buffer, 0, StreamBufferSize)) != 0)
                {
                    processor.ProcessBlock(buffer.AsSpan(0, length));
                }

                return processor.ProcessFinalBlock(ReadOnlySpan<byte>.Empty);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }
        }

        private static async Task<Hash> ComputeStreamHashAsync(Stream stream, HashProcessor processor, CancellationToken cancellationToken)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(StreamBufferSize);
            try
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int length = await stream.ReadAsync(buffer.AsMemory(0, StreamBufferSize), cancellationToken).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    if (length == 0)
                    {
                        return processor.ProcessFinalBlock(ReadOnlySpan<byte>.Empty);
                    }

                    processor.ProcessBlock(buffer.AsSpan(0, length));
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }
        }

        private static ReadOnlySpan<byte> ValidateData(byte[] data, int length)
        {
            ArgumentNullException.ThrowIfNull(data);
            ArgumentOutOfRangeException.ThrowIfNegative(length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, data.Length);
            return data.AsSpan(0, length);
        }

        private void ThrowIfUnavailable()
        {
            ObjectDisposedException.ThrowIf(this.disposed, this);
            if (this.finalized)
            {
                throw new InvalidOperationException("The hash has been finalized. Call Reset() before processing more data.");
            }
        }

        private void AppendData(ReadOnlySpan<byte> data)
        {
            this.algorithm.AppendData(data);
            this.BytesProcessed += data.Length;
        }

        private Hash FinalizeHash(ReadOnlySpan<byte> data)
        {
            this.algorithm.AppendData(data);
            byte[] value = this.algorithm.GetHashAndReset();
            this.BytesProcessed += data.Length;
            this.finalized = true;
            return new Hash(value, this.AlgorithmName);
        }
    }
}
