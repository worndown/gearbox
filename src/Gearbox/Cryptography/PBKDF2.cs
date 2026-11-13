using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Gearbox.Cryptography
{
    /// <summary>
    /// Implements password-based key derivation functionality (PBKDF2)
    /// by using an HMAC based pseudo-random number generator.
    /// 
    /// Initialize an instance of this class by supplying a password, salt and iteration count.
    /// Retrieve key material through calls to the GetBytes method.
    /// </summary>
    public class PBKDF2 : DeriveBytes
    {
        /// <summary>
        /// Minimal iteration count.
        /// </summary>
        private const int MinIterationCount = 1;

        /// <summary>
        /// Maximum iteration count to set some practical cap.
        /// </summary>
        private const int MaxIterationCount = 100000000;

        /// <summary>
        /// Default number of iterations. Aligned with OWASP guidance for PBKDF2-HMAC-SHA512.
        /// </summary>
        private const int DefaultIterationCount = 210000;

        /// <summary>
        /// Minimal salt size in bytes.
        /// </summary>
        public const int MinSaltSize = 8;

        /// <summary>
        /// Maximum salt length in bytes.
        /// This should be more than sufficient for all practical purposes.
        /// </summary>
        public const int MaxSaltSize = 64;

        /// <summary>
        /// The HMAC function.
        /// </summary>
        private readonly HMACSHA512 hmac;

        /// <summary>
        /// Block size in bytes (equals to hash size).
        /// </summary>
        private const int BlockSize = SHA512.HashSizeInBytes;

        /// <summary>
        /// Key salt.
        /// </summary>
        private readonly byte[] salt;

        /// <summary>
        /// Progress reporting.
        /// </summary>
        private readonly IProgress<int>? progress;

        /// <summary>
        /// Cancellation token.
        /// </summary>
        private readonly CancellationToken cancellationToken;

        /// <summary>
        /// Current block number.
        /// </summary>
        private uint currentBlock;

        /// <summary>
        /// Buffer with unused key bytes from the last block.
        /// </summary>
        private readonly byte[] buffer;

        /// <summary>
        /// Position in the buffer where key bytes start.
        /// </summary>
        private int startIndex;

        /// <summary>
        /// Position in the buffer where key bytes end.
        /// </summary>
        private int endIndex;

        private bool disposed;

        /// <summary>
        /// Initializes a new instance of the PBKDF2 class using password to derive the key.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        public PBKDF2(string password)
            : this(password, MinSaltSize)
        {
        }

        /// <summary>
        /// Initializes a new instance of the PBKDF2 class using password and salt to derive the key.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="salt">The key salt used to derive the key.</param>
        public PBKDF2(string password, byte[] salt)
            : this(password, salt, DefaultIterationCount, null, CancellationToken.None)
        {
        }

        /// <summary>
        /// Initializes a new instance of the PBKDF2 class using password and salt to derive the key.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="salt">The key salt used to derive the key.</param>
        public PBKDF2(byte[] password, byte[] salt)
            : this(password, salt, DefaultIterationCount, null, CancellationToken.None)
        {
        }

        /// <summary>
        /// Initializes a new instance of the PBKDF2 class using password and salt length to derive the key. 
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="saltSize">The size, in bytes, of the random salt to generate.</param>
        public PBKDF2(string password, int saltSize)
            : this(password, saltSize, DefaultIterationCount, null, CancellationToken.None)
        {
        }

        /// <summary>
        /// Initializes a new instance of the PBKDF2 class using password, salt and number of iterations to derive the key. 
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="salt">The key salt used to derive the key.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="progress">Reports progress from 0 to 100 for each 64-byte key block.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <remarks>The default is 210,000 iterations. Choose an iteration count appropriate for your password policy and hardware.</remarks>
        public PBKDF2(string password, byte[] salt, int iterations, IProgress<int>? progress, CancellationToken cancellationToken)
            : this(Encoding.UTF8.GetBytes(password), salt, iterations, progress, cancellationToken, clearPassword: true)
        {
        }

        /// <summary>
        /// Initializes a new instance of the PBKDF2 class using password, salt size and number of iterations to derive the key. 
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="saltSize">The size, in bytes, of the random salt to generate.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="progress">Reports progress from 0 to 100 for each 64-byte key block.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <remarks>The default is 210,000 iterations. Choose an iteration count appropriate for your password policy and hardware.</remarks>
        public PBKDF2(string password, int saltSize, int iterations, IProgress<int>? progress, CancellationToken cancellationToken)
            : this(password, GenerateSalt(saltSize), iterations, progress, cancellationToken)
        {
        }

        /// <summary>
        /// Initializes a new instance of the PBKDF2 class using password, salt and number of iterations to derive the key.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="salt">The key salt used to derive the key.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="progress">Reports progress from 0 to 100 for each 64-byte key block.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <remarks>The default is 210,000 iterations. Choose an iteration count appropriate for your password policy and hardware.</remarks>
        public PBKDF2(byte[] password, byte[] salt, int iterations, IProgress<int>? progress, CancellationToken cancellationToken)
            : this(password, salt, iterations, progress, cancellationToken, clearPassword: false)
        {
        }

        private PBKDF2(byte[] password, byte[] salt, int iterations, IProgress<int>? progress, CancellationToken cancellationToken, bool clearPassword)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(password);
                ValidateParameters(salt, iterations);

                this.salt = (byte[])salt.Clone();
                this.IterationCount = iterations;
                this.buffer = new byte[BlockSize];
                this.currentBlock = 1;
                this.progress = progress;
                this.cancellationToken = cancellationToken;
                this.hmac = new HMACSHA512(password);
            }
            finally
            {
                if (clearPassword)
                {
                    // String overloads own this UTF-8 copy; byte[] overloads retain caller ownership.
                    CryptographicOperations.ZeroMemory(password);
                }
            }
        }

        /// <summary>
        /// Gets the number of iterations for the operation.
        /// </summary>
        public int IterationCount { get; }

        /// <summary>
        /// Gets the key salt value for the operation.
        /// </summary>
        public byte[] Salt => (byte[])this.salt.Clone();

        #region DeriveBytes implementation

        /// <summary>
        /// Returns the pseudo-random key for this object.
        /// </summary>
        /// <param name="cb">The number of pseudo-random key bytes to generate.</param>
        /// <returns>A byte array filled with pseudo-random key bytes.</returns>
        /// <remarks>
        /// Repeated calls to this method will not generate the same key; instead,
        /// appending two calls of the GetBytes method with a cb parameter value of 20 is
        /// the equivalent of calling the GetBytes method once with a cb parameter value of 40.
        /// </remarks>
        public override byte[] GetBytes(int cb)
        {
            ObjectDisposedException.ThrowIf(this.disposed, this);
            // Maximum array size is 2147483591
            if (cb is < 1 or > int.MaxValue - 56)
            {
                throw new ArgumentOutOfRangeException(nameof(cb));
            }

            this.cancellationToken.ThrowIfCancellationRequested();
            byte[] key = new byte[cb];
            Span<byte> block = stackalloc byte[BlockSize];
            try
            {
                int offset = 0;
                int bufferedCount = Math.Min(cb, this.endIndex - this.startIndex);
                if (bufferedCount > 0)
                {
                    Span<byte> bufferedBytes = this.buffer.AsSpan(this.startIndex, bufferedCount);
                    bufferedBytes.CopyTo(key);
                    CryptographicOperations.ZeroMemory(bufferedBytes);
                    this.startIndex += bufferedCount;
                    offset = bufferedCount;
                    if (this.startIndex == this.endIndex)
                    {
                        this.startIndex = this.endIndex = 0;
                    }
                }

                while (offset < cb)
                {
                    this.DeriveKey(block);
                    int count = Math.Min(cb - offset, BlockSize);
                    block[..count].CopyTo(key.AsSpan(offset));
                    if (count < BlockSize)
                    {
                        block[count..].CopyTo(this.buffer);
                        this.startIndex = 0;
                        this.endIndex = BlockSize - count;
                    }

                    offset += count;
                }

                return key;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(key);
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(block);
            }
        }

        /// <summary>
        /// Resets the state of the operation.
        /// </summary>
        public override void Reset()
        {
            ObjectDisposedException.ThrowIf(this.disposed, this);
            CryptographicOperations.ZeroMemory(this.buffer);
            this.hmac.Initialize();
            this.currentBlock = 1;
            this.startIndex = this.endIndex = 0;
        }

        #endregion

        /// <summary>
        /// Disposes this object.
        /// </summary>
        /// <param name="disposing">Whether object is being disposed.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && !this.disposed)
            {
                this.disposed = true;
                this.hmac.Dispose();
                CryptographicOperations.ZeroMemory(this.buffer);
                CryptographicOperations.ZeroMemory(this.salt);
                this.startIndex = this.endIndex = 0;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Derives next key block.
        /// </summary>
        /// <param name="result">Receives the next 64-byte key block.</param>
        private void DeriveKey(Span<byte> result)
        {
            Span<byte> input = stackalloc byte[MaxSaltSize + sizeof(uint)];
            Span<byte> hash = stackalloc byte[BlockSize];
            Span<byte> nextHash = stackalloc byte[BlockSize];
            try
            {
                this.progress?.Report(0);
                this.cancellationToken.ThrowIfCancellationRequested();

                this.salt.CopyTo(input);
                BinaryPrimitives.WriteUInt32BigEndian(input.Slice(this.salt.Length, sizeof(uint)), this.currentBlock);
                this.ComputeHash(input[..(this.salt.Length + sizeof(uint))], hash);
                hash.CopyTo(result);

                int percentComplete = 0;
                for (int i = 2; i <= this.IterationCount; ++i)
                {
                    this.cancellationToken.ThrowIfCancellationRequested();
                    this.ComputeHash(hash, nextHash);
                    for (int j = 0; j < BlockSize; ++j)
                    {
                        result[j] ^= nextHash[j];
                    }

                    Span<byte> previousHash = hash;
                    hash = nextHash;
                    nextHash = previousHash;

                    if (this.progress is not null)
                    {
                        int percent = (int)((long)i * 100 / this.IterationCount);
                        if (percent > percentComplete)
                        {
                            this.progress.Report(percent);
                            percentComplete = percent;
                        }
                    }
                }

                if (percentComplete < 100)
                {
                    this.progress?.Report(100);
                }

                this.cancellationToken.ThrowIfCancellationRequested();
                ++this.currentBlock;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
                CryptographicOperations.ZeroMemory(hash);
                CryptographicOperations.ZeroMemory(nextHash);
            }
        }

        private void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            if (!this.hmac.TryComputeHash(source, destination, out _))
            {
                throw new CryptographicException("Unable to compute a PBKDF2 hash block.");
            }
        }

        internal static void ValidateParameters(byte[] salt, int iterations)
        {
            ArgumentNullException.ThrowIfNull(salt);
            if (salt.Length is < MinSaltSize or > MaxSaltSize)
            {
                throw new ArgumentOutOfRangeException(nameof(salt), $"Invalid salt length. Must be {MinSaltSize}-{MaxSaltSize} bytes long.");
            }

            if (iterations is < MinIterationCount or > MaxIterationCount)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations), "Invalid iteration count.");
            }
        }

        /// <summary>
        /// Generates random salt value of requested length.
        /// </summary>
        /// <param name="saltSize">Salt length in bytes.</param>
        /// <returns>Random salt value.</returns>
        private static byte[] GenerateSalt(int saltSize)
        {
            if (saltSize is < MinSaltSize or > MaxSaltSize)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(saltSize),
                    $"Invalid salt length. Must be {MinSaltSize}-{MaxSaltSize} bytes long.");
            }

            return RandomNumberGenerator.GetBytes(saltSize);
        }
    }
}
