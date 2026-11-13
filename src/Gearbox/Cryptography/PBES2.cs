using System.Security.Cryptography;
using System.Text;

namespace Gearbox.Cryptography
{
    /// <summary>
    /// Password-based encryption standard. Combines a password-based key derivation
    /// function (PBKDF2) with an underlying authenticated encryption scheme (AES-256-GCM).
    /// </summary>
    /// <remarks>
    /// The full 256-bit AES key is always derived; the GCM nonce is generated per message
    /// by the cipher itself and is not derived from the password.
    /// </remarks>
    public static class PBES2
    {
        /// <summary>
        /// Uses PBKDF2 initialized with the HMACSHA512 function to derive a key based on a password,
        /// salt and number of iterations. Creates an authenticated AES-256-GCM cipher using the derived key.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="salt">The key salt used to derive the key. Must be 8–64 bytes long.</param>
        /// <param name="iterations">The number of iterations for the operation. Must be 1–100,000,000.</param>
        /// <param name="progress">Reports key derivation progress from 0 to 100.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Initialized symmetric cipher.</returns>
        public static Cipher CreateCipher(string password, byte[] salt, int iterations, IProgress<int>? progress, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(password);
            PBKDF2.ValidateParameters(salt, iterations);
            cancellationToken.ThrowIfCancellationRequested();

            if (progress is null && !cancellationToken.CanBeCanceled)
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                Span<byte> key = stackalloc byte[Cipher.KeySizeBits / 8];
                try
                {
                    Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, key, iterations, HashAlgorithmName.SHA512);
                    return new Cipher(key);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                    CryptographicOperations.ZeroMemory(passwordBytes);
                }
            }

            using (PBKDF2 pbkdf2 = new PBKDF2(password, salt, iterations, progress, cancellationToken))
            {
                return new Cipher(pbkdf2);
            }
        }

        /// <summary>
        /// Uses PBKDF2 with HMACSHA512 to derive a key based on the password, salt and number of iterations.
        /// Then creates an authenticated AES-256-GCM cipher using the derived key.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="salt">The key salt used to derive the key. Must be 8–64 bytes long.</param>
        /// <param name="iterations">The number of iterations for the operation. Must be 1–100,000,000.</param>
        /// <param name="progress">Reports key derivation progress from 0 to 100.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Task representing async operation.</returns>
        public static Task<Cipher> CreateCipherAsync(string password, byte[] salt, int iterations, IProgress<int>? progress, CancellationToken cancellationToken)
        {
            return Task.Run(() => CreateCipher(password, salt, iterations, progress, cancellationToken), cancellationToken);
        }
    }
}
