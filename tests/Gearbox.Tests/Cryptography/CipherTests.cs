using System.Security.Cryptography;
using Gearbox.Cryptography;

namespace Gearbox.Tests.Cryptography
{
    [TestClass]
    public class CipherTests
    {
        private static readonly byte[] Key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        private static readonly byte[] AssociatedData = { 1, 2, 3 };

        [TestMethod]
        public void Decrypt_NistAes256GcmVector_ReturnsKnownPlaintext()
        {
            // NIST AES-256-GCM vector: zero key, 96-bit zero nonce, one zero plaintext block, no AAD.
            byte[] blob = Convert.FromHexString(
                "000000000000000000000000" +
                "D0D1C8A799996BF0265B98B5D48AB919" +
                "CEA7403D4D606B6E074EC5D3BAF39D18");
            using Cipher cipher = new Cipher(new byte[32]);

            CollectionAssert.AreEqual(new byte[16], cipher.Decrypt(blob));
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(16)]
        [DataRow(17)]
        [DataRow(1024)]
        public void Encrypt_VariedPlaintextLengths_InteroperatesWithBcl(int length)
        {
            byte[] plainText = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
            byte[] original = (byte[])plainText.Clone();
            byte[] decrypted = new byte[length];
            using Cipher cipher = new Cipher(Key);
            using AesGcm aes = new AesGcm(Key, 16);

            byte[] blob = cipher.Encrypt(plainText, AssociatedData);
            Assert.HasCount(12 + 16 + length, blob);
            aes.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(28), blob.AsSpan(12, 16), decrypted, AssociatedData);

            CollectionAssert.AreEqual(original, decrypted);
            CollectionAssert.AreEqual(original, plainText);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(16)]
        [DataRow(17)]
        [DataRow(1024)]
        public void Decrypt_BclCiphertext_RecoversPlaintext(int length)
        {
            byte[] plainText = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
            byte[] blob = new byte[28 + length];
            Convert.FromHexString("101112131415161718191A1B").CopyTo(blob, 0);
            using AesGcm aes = new AesGcm(Key, 16);
            aes.Encrypt(blob.AsSpan(0, 12), plainText, blob.AsSpan(28), blob.AsSpan(12, 16), AssociatedData);
            byte[] original = (byte[])blob.Clone();
            using Cipher cipher = new Cipher(Key);

            CollectionAssert.AreEqual(plainText, cipher.Decrypt(blob, AssociatedData));
            CollectionAssert.AreEqual(original, blob);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(11)]
        [DataRow(12)]
        [DataRow(27)]
        [DataRow(28)]
        [DataRow(43)]
        public void Decrypt_TamperingWithNonceTagOrCiphertext_FailsAuthentication(int offset)
        {
            using Cipher cipher = new Cipher(Key);
            byte[] blob = cipher.Encrypt(new byte[16], AssociatedData);
            blob[offset] ^= 1;

            Assert.ThrowsExactly<AuthenticationTagMismatchException>(() => cipher.Decrypt(blob, AssociatedData));
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(11)]
        [DataRow(12)]
        [DataRow(27)]
        public void Decrypt_ShortBlob_Throws(int length)
        {
            using Cipher cipher = new Cipher(Key);

            Assert.ThrowsExactly<CryptographicException>(() => cipher.Decrypt(new byte[length]));
        }

        [TestMethod]
        [DataRow(-1)]
        [DataRow(1)]
        public void Decrypt_TruncatedOrExtendedCiphertext_FailsAuthentication(int lengthChange)
        {
            using Cipher cipher = new Cipher(Key);
            byte[] blob = cipher.Encrypt(new byte[16]);
            Array.Resize(ref blob, blob.Length + lengthChange);

            Assert.ThrowsExactly<AuthenticationTagMismatchException>(() => cipher.Decrypt(blob));
        }

        [TestMethod]
        public void Decrypt_MissingAssociatedData_FailsAuthentication()
        {
            using Cipher cipher = new Cipher(Key);
            byte[] blob = cipher.Encrypt(Array.Empty<byte>(), AssociatedData);

            Assert.ThrowsExactly<AuthenticationTagMismatchException>(() => cipher.Decrypt(blob));
            Assert.HasCount(0, cipher.Decrypt(blob, AssociatedData));
        }

        [TestMethod]
        public void ConstructorAndMethods_NullInputs_ThrowArgumentNullException()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new Cipher((byte[])null!));
            Assert.ThrowsExactly<ArgumentNullException>(() => new Cipher((DeriveBytes)null!));
            using Cipher cipher = new Cipher(Key);

            Assert.ThrowsExactly<ArgumentNullException>(() => cipher.Encrypt(null!));
            Assert.ThrowsExactly<ArgumentNullException>(() => cipher.Decrypt(null!));
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(15)]
        [DataRow(17)]
        [DataRow(33)]
        public void Constructor_InvalidKeyLength_ThrowsWithoutChangingCallerKey(int length)
        {
            byte[] key = Enumerable.Repeat((byte)42, length).ToArray();
            byte[] original = (byte[])key.Clone();

            ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => new Cipher(key));

            Assert.AreEqual("key", exception.ParamName);
            CollectionAssert.AreEqual(original, key);
        }

        [TestMethod]
        [DataRow(16)]
        [DataRow(24)]
        [DataRow(32)]
        public void Constructor_CallerKeyMutation_KeepsIndependentKeyCopy(int length)
        {
            byte[] callerKey = Key[..length];
            byte[] original = (byte[])callerKey.Clone();
            using Cipher cipher = new Cipher(callerKey);
            using Cipher other = new Cipher(original);
            Array.Fill(callerKey, (byte)255);

            Assert.AreEqual(length * 8, cipher.KeySize);
            CollectionAssert.AreEqual(new byte[] { 4, 5, 6 }, other.Decrypt(cipher.Encrypt(new byte[] { 4, 5, 6 })));
            cipher.Dispose();
            cipher.Dispose();
            CollectionAssert.AreEqual(Enumerable.Repeat((byte)255, length).ToArray(), callerKey);
        }

        [TestMethod]
        public void Encrypt_DisposedCipher_ThrowsObjectDisposedException()
        {
            using Cipher cipher = PBES2.CreateCipher("password", new byte[8], 2, null, CancellationToken.None);
            cipher.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => cipher.Encrypt(new byte[] { 1, 2, 3 }));
        }

        [TestMethod]
        public void Decrypt_DisposedCipher_RejectsZeroKeyForgery()
        {
            byte[] forgedBlob = new byte[31];
            using (AesGcm aes = new AesGcm(new byte[32], 16))
            {
                aes.Encrypt(forgedBlob.AsSpan(0, 12), new byte[] { 1, 2, 3 }, forgedBlob.AsSpan(28), forgedBlob.AsSpan(12, 16));
            }

            using Cipher cipher = PBES2.CreateCipher("password", new byte[8], 2, null, CancellationToken.None);
            cipher.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => cipher.Decrypt(forgedBlob));
        }

        [TestMethod]
        public void Constructor_DerivedKey_ClearsTemporaryKey()
        {
            using TrackingDeriveBytes pbkdf2 = new TrackingDeriveBytes();
            using Cipher cipher = new Cipher(pbkdf2);

            Assert.HasCount(32, pbkdf2.LastDerivedKey);
            CollectionAssert.AreEqual(new byte[32], pbkdf2.LastDerivedKey);
        }

        [TestMethod]
        public void Constructor_InvalidDerivedKey_ClearsTemporaryKey()
        {
            using TrackingDeriveBytes pbkdf2 = new TrackingDeriveBytes { ReturnedLength = 15 };

            Assert.ThrowsExactly<ArgumentException>(() => new Cipher(pbkdf2));

            Assert.HasCount(15, pbkdf2.LastDerivedKey);
            CollectionAssert.AreEqual(new byte[15], pbkdf2.LastDerivedKey);
        }

        private sealed class TrackingDeriveBytes : DeriveBytes
        {
            public byte[] LastDerivedKey { get; private set; } = Array.Empty<byte>();

            public int? ReturnedLength { get; init; }

            public override byte[] GetBytes(int cb)
            {
                this.LastDerivedKey = Enumerable.Repeat((byte)42, this.ReturnedLength ?? cb).ToArray();
                return this.LastDerivedKey;
            }

            public override void Reset() { }
        }
    }
}
