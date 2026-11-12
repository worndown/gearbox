using System.Security.Cryptography;

namespace Gearbox.Cryptography
{
    /// <summary>
    /// Authenticated symmetric cipher for data encryption/decryption.
    /// Uses AES-256 in GCM (AEAD) mode: every call generates a fresh random nonce and
    /// produces an authentication tag, providing confidentiality, integrity and authenticity.
    /// </summary>
    public sealed class Cipher : IDisposable
    {
        /// <summary>
        /// AES key size, in bits.
        /// </summary>
        public const int KeySizeBits = 256;

        /// <summary>
        /// Nonce (IV) size, in bytes. 96 bits is the size recommended for AES-GCM.
        /// </summary>
        private const int NonceSize = 12;

        /// <summary>
        /// Authentication tag size, in bytes.
        /// </summary>
        private const int TagSize = 16;

        /// <summary>
        /// The encryption key.
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// Initializes a new instance of the cipher using key material derived from PBKDF2.
        /// </summary>
        /// <param name="pbkdf2">Fully initialized key-derivation function.</param>
        internal Cipher(DeriveBytes pbkdf2)
            : this(pbkdf2.GetBytes(KeySizeBits / 8))
        {
        }

        /// <summary>
        /// Initializes a new instance of the cipher using the provided key.
        /// </summary>
        /// <param name="key">Encryption key. Must be a valid AES key length (16, 24 or 32 bytes).</param>
        internal Cipher(byte[] key)
        {
            ArgumentNullException.ThrowIfNull(key);
            this.key = (byte[])key.Clone();
        }

        /// <summary>
        /// Gets the size, in bits, of the secret key used by the cipher.
        /// </summary>
        public int KeySize => this.key.Length * 8;

        /// <summary>
        /// Encrypts the provided plaintext.
        /// </summary>
        /// <param name="plainText">Data to encrypt.</param>
        /// <param name="associatedData">
        /// Optional associated data that is authenticated but not encrypted. The same value must be supplied
        /// to <see cref="Decrypt"/>; this binds the ciphertext to a context (e.g. record id and field).
        /// </param>
        /// <returns>Encrypted blob laid out as nonce || tag || ciphertext.</returns>
        public byte[] Encrypt(byte[] plainText, ReadOnlySpan<byte> associatedData = default)
        {
            ArgumentNullException.ThrowIfNull(plainText);

            byte[] result = new byte[NonceSize + TagSize + plainText.Length];
            Span<byte> nonce = result.AsSpan(0, NonceSize);
            Span<byte> tag = result.AsSpan(NonceSize, TagSize);
            Span<byte> cipherText = result.AsSpan(NonceSize + TagSize);

            RandomNumberGenerator.Fill(nonce);

            using (AesGcm aes = new AesGcm(this.key, TagSize))
            {
                aes.Encrypt(nonce, plainText, cipherText, tag, associatedData);
            }

            return result;
        }

        /// <summary>
        /// Decrypts a blob produced by <see cref="Encrypt"/>.
        /// </summary>
        /// <param name="blob">Encrypted blob laid out as nonce || tag || ciphertext.</param>
        /// <param name="associatedData">
        /// The same associated data that was supplied to <see cref="Encrypt"/>. A mismatch fails authentication.
        /// </param>
        /// <returns>Decrypted plaintext.</returns>
        /// <exception cref="CryptographicException">
        /// Authentication failed because the key, the associated data, or the data itself did not match.
        /// </exception>
        public byte[] Decrypt(byte[] blob, ReadOnlySpan<byte> associatedData = default)
        {
            ArgumentNullException.ThrowIfNull(blob);
            if (blob.Length < NonceSize + TagSize)
            {
                throw new CryptographicException("Encrypted blob is too short to be valid.");
            }

            ReadOnlySpan<byte> nonce = blob.AsSpan(0, NonceSize);
            ReadOnlySpan<byte> tag = blob.AsSpan(NonceSize, TagSize);
            ReadOnlySpan<byte> cipherText = blob.AsSpan(NonceSize + TagSize);

            byte[] plainText = new byte[cipherText.Length];
            using (AesGcm aes = new AesGcm(this.key, TagSize))
            {
                aes.Decrypt(nonce, cipherText, tag, plainText, associatedData);
            }

            return plainText;
        }

        /// <summary>
        /// Disposes this instance, zeroing the key material.
        /// </summary>
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(this.key);
        }
    }
}
