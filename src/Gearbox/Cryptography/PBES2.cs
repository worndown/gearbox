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
        /// <param name="salt">The key salt used to derive the key. Must be 8 bytes or longer.</param>
        /// <param name="iterations">The number of iterations for the operation. Must be greater than 0.</param>
        /// <param name="progress">The object for key derivation progress reporting.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Initialized symmetric cipher.</returns>
        public static Cipher CreateCipher(string password, byte[] salt, int iterations, IProgress<int>? progress, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(password);
            using (PBKDF2 pbkdf2 = new PBKDF2(Encoding.UTF8.GetBytes(password), salt, iterations, progress, cancellationToken))
            {
                return new Cipher(pbkdf2);
            }
        }

        /// <summary>
        /// Uses PBKDF2 with HMACSHA512 to derive a key based on the password, salt and number of iterations.
        /// Then creates an authenticated AES-256-GCM cipher using the derived key.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="salt">The key salt used to derive the key. Must be 8 bytes or longer.</param>
        /// <param name="iterations">The number of iterations for the operation. Must be greater than 0.</param>
        /// <param name="progress">The object for key derivation progress reporting.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>Task representing async operation.</returns>
        public static Task<Cipher> CreateCipherAsync(string password, byte[] salt, int iterations, IProgress<int>? progress, CancellationToken cancellationToken)
        {
            return Task.Run(() => CreateCipher(password, salt, iterations, progress, cancellationToken));
        }
    }
}
