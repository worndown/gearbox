using System.Diagnostics;
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
        private readonly int blockSize;

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
        private byte[] buffer;

        /// <summary>
        /// Position in the buffer where key bytes start.
        /// </summary>
        private int startIndex;

        /// <summary>
        /// Position in the buffer where key bytes end.
        /// </summary>
        private int endIndex;

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
        /// <param name="progress">The object for key derivation progress reporting.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <remarks>The minimum recommended number of iterations is 1000.</remarks>
        public PBKDF2(string password, byte[] salt, int iterations, IProgress<int>? progress, CancellationToken cancellationToken)
            : this(Encoding.UTF8.GetBytes(password), salt, iterations, progress, cancellationToken)
        {
        }

        /// <summary>
        /// Initializes a new instance of the PBKDF2 class using password, salt size and number of iterations to derive the key. 
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="saltSize">The size, in bytes, of the random salt to generate.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="progress">The object for key derivation progress reporting.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <remarks>The minimum recommended number of iterations is 1000.</remarks>
        public PBKDF2(string password, int saltSize, int iterations, IProgress<int>? progress, CancellationToken cancellationToken)
            : this(Encoding.UTF8.GetBytes(password), GenerateSalt(saltSize), iterations, progress, cancellationToken)
        {
        }

        /// <summary>
        /// Initializes a new instance of the PBKDF2 class using password, salt and number of iterations to derive the key.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="salt">The key salt used to derive the key.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="progress">The object for key derivation progress reporting.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <remarks>The minimum recommended number of iterations is 1000.</remarks>
        public PBKDF2(byte[] password, byte[] salt, int iterations, IProgress<int>? progress, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(salt);

            if (salt.Length is < MinSaltSize or > MaxSaltSize)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(salt),
                    $"Invalid salt length. Must be {MinSaltSize}-{MaxSaltSize} bytes long.");
            }

            if (iterations is < MinIterationCount or > MaxIterationCount)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations), "Invalid iteration count.");
            }

            this.salt = (byte[])salt.Clone();
            this.IterationCount = iterations;
            this.hmac = new HMACSHA512 { Key = password };
            this.blockSize = this.hmac.HashSize / 8;
            this.buffer = new byte[this.blockSize];
            this.currentBlock = 1;
            this.progress = progress;
            this.cancellationToken = cancellationToken;
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
            // Maximum array size is 2147483591
            if (cb is < 1 or > int.MaxValue - 56)
            {
                throw new ArgumentOutOfRangeException(nameof(cb));
            }

            byte[] key = new byte[cb];
            int offset = 0;
            int size = this.endIndex - this.startIndex;
            if (size > 0)
            {
                if (cb >= size)
                {
                    Buffer.BlockCopy(this.buffer, this.startIndex, key, 0, size);
                    this.startIndex = this.endIndex = 0;
                    offset += size;
                }
                else
                {
                    Buffer.BlockCopy(this.buffer, this.startIndex, key, 0, cb);
                    this.startIndex += cb;
                    return key;
                }
            }

            Debug.Assert(this.startIndex == 0 && this.endIndex == 0);

            while (offset < cb)
            {
                byte[] blockTransformed = this.DeriveKey();
                int remainder = cb - offset;
                if (remainder > this.blockSize)
                {
                    Buffer.BlockCopy(blockTransformed, 0, key, offset, this.blockSize);
                    offset += this.blockSize;
                }
                else
                {
                    Buffer.BlockCopy(blockTransformed, 0, key, offset, remainder);
                    Buffer.BlockCopy(blockTransformed, remainder, this.buffer, this.startIndex, this.blockSize - remainder);
                    this.endIndex += (this.blockSize - remainder);
                    return key;
                }
            }

            return key;
        }

        /// <summary>
        /// Resets the state of the operation.
        /// </summary>
        public override void Reset()
        {
            Array.Clear(this.buffer, 0, this.buffer.Length);

            this.buffer = new byte[this.blockSize];
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
            base.Dispose(disposing);

            if (disposing)
            {
                this.hmac.Dispose();
                Array.Clear(this.buffer, 0, this.buffer.Length);
                Array.Clear(this.salt, 0, this.salt.Length);
            }
        }

        /// <summary>
        /// Derives next key block.
        /// </summary>
        /// <returns>Next key block.</returns>
        private byte[] DeriveKey()
        {
            int percentComplete = 0;
            int reportFrequency = this.IterationCount / 100;

            // Convert current block number into a four-byte, big-endian array.
            byte[] blockIndex = BitConverter.GetBytes(this.currentBlock);
            if (BitConverter.IsLittleEndian)
            {
                byte b = blockIndex[0];
                blockIndex[0] = blockIndex[3];
                blockIndex[3] = b;

                b = blockIndex[1];
                blockIndex[1] = blockIndex[2];
                blockIndex[2] = b;
            }

            this.hmac.TransformBlock(this.salt, 0, this.salt.Length, this.salt, 0);
            this.hmac.TransformFinalBlock(blockIndex, 0, blockIndex.Length);
            byte[]? hash = this.hmac.Hash;
            Debug.Assert(hash != null);

            byte[] result = hash;
            this.hmac.Initialize();

            this.progress?.Report(0);

            for (int i = 2; i <= this.IterationCount; ++i)
            {
                this.cancellationToken.ThrowIfCancellationRequested();
                hash = this.hmac.ComputeHash(hash);
                for (int j = 0; j < this.blockSize; ++j)
                {
                    result[j] ^= hash[j];
                }

                // If number of iteration < 100 we will report 0 and 100% only.
                if (reportFrequency > 0 && (i % reportFrequency == 0))
                {
                    this.progress?.Report(++percentComplete);
                }
            }

            if (percentComplete < 100)
            {
                this.progress?.Report(100);
            }

            ++this.currentBlock;
            return result;
        }

        /// <summary>
        /// Generates random salt value of requested length.
        /// </summary>
        /// <param name="saltLen">Salt length in bytes.</param>
        /// <returns>Random salt value.</returns>
        private static byte[] GenerateSalt(int saltLen)
        {
            if (saltLen is < MinSaltSize or > MaxSaltSize)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(salt),
                    $"Invalid salt length. Must be {MinSaltSize}-{MaxSaltSize} bytes long.");
            }

            return RandomNumberGenerator.GetBytes(saltLen);
        }
    }
}
