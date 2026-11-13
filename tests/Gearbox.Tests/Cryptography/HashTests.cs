using Gearbox.Cryptography;

namespace Gearbox.Tests.Cryptography
{
    [TestClass]
    public class HashTests
    {
        [TestMethod]
        [DataRow(new byte[] { }, "")]
        [DataRow(new byte[] { 0 }, "SHA256")]
        [DataRow(new byte[] { 0, 1, 171, 255 }, "SHA512")]
        [DataRow(new byte[] { 255, 128, 0 }, "Custom algorithm")]
        public void Constructor_ValueAndName_PreservesInputs(byte[] value, string name)
        {
            byte[] original = (byte[])value.Clone();

            Hash hash = new Hash(value, name);

            Assert.AreEqual(name, hash.Name);
            CollectionAssert.AreEqual(original, hash.Value);
            CollectionAssert.AreEqual(original, value);
        }

        [TestMethod]
        [DataRow(new byte[] { }, "")]
        [DataRow(new byte[] { 0 }, "00")]
        [DataRow(new byte[] { 1, 10, 15 }, "010A0F")]
        [DataRow(new byte[] { 0, 1, 171, 205, 239, 255 }, "0001ABCDEFFF")]
        [DataRow(new byte[] { 128, 254, 255 }, "80FEFF")]
        public void ToString_ByteValues_ReturnsUppercaseHex(byte[] value, string expected)
        {
            Hash hash = new Hash(value, "SHA256");

            Assert.AreEqual(expected, hash.ToString());
            CollectionAssert.AreEqual(value, hash.Value);
        }

        [TestMethod]
        public void ToString_DifferentAlgorithmNames_ReturnsSameHex()
        {
            Hash first = new Hash([0, 171, 255], "SHA256");
            Hash second = new Hash([0, 171, 255], "SHA512");

            Assert.AreEqual("00ABFF", first.ToString());
            Assert.AreEqual("00ABFF", second.ToString());
        }

        [TestMethod]
        [DataRow("", "SHA256", "", "SHA256", true)]
        [DataRow("00", "SHA256", "00", "SHA256", true)]
        [DataRow("0001ABCDEF", "SHA256", "0001ABCDEF", "SHA256", true)]
        [DataRow("FF8000", "", "FF8000", "", true)]
        [DataRow("000102", "SHA256", "FF0102", "SHA256", false)]
        [DataRow("000102", "SHA256", "00FF02", "SHA256", false)]
        [DataRow("000102", "SHA256", "0001FF", "SHA256", false)]
        [DataRow("000102", "SHA256", "020100", "SHA256", false)]
        [DataRow("000102", "SHA256", "0001", "SHA256", false)]
        [DataRow("000102", "SHA256", "00010200", "SHA256", false)]
        [DataRow("", "SHA256", "00", "SHA256", false)]
        [DataRow("000102", "SHA256", "000102", "SHA512", false)]
        [DataRow("000102", "SHA256", "000102", "sha256", false)]
        [DataRow("000102", "SHA256", "000102", "SHA256 ", false)]
        [DataRow("", "SHA256", "", "SHA512", false)]
        public void Equality_NameAndByteSequence_AgreesAcrossComparisons(
            string leftValue, string leftName, string rightValue, string rightName, bool expected)
        {
            Hash left = new Hash(Convert.FromHexString(leftValue), leftName);
            Hash right = new Hash(Convert.FromHexString(rightValue), rightName);
            IEquatable<Hash> equatable = left;

            Assert.AreNotSame(left, right);
            Assert.AreEqual(expected, left.Equals(right));
            Assert.AreEqual(expected, right.Equals(left));
            Assert.AreEqual(expected, left.Equals((object)right));
            Assert.AreEqual(expected, right.Equals((object)left));
            Assert.AreEqual(expected, equatable.Equals(right));
            Assert.AreEqual(expected, left == right);
            Assert.AreEqual(expected, right == left);
            Assert.AreEqual(!expected, left != right);
            Assert.AreEqual(!expected, right != left);
        }

        [TestMethod]
        public void Equality_SameInstance_ReturnsTrue()
        {
            Hash hash = new Hash([0, 1, 255], "SHA256");
            Hash same = hash;

            Assert.IsTrue(hash.Equals(same));
            Assert.IsTrue(hash.Equals((object)same));
            Assert.IsTrue(hash == same);
            Assert.IsFalse(hash != same);
        }

        [TestMethod]
        public void Equals_EqualInstances_IsTransitive()
        {
            Hash first = new Hash([0, 1, 255], "SHA256");
            Hash second = new Hash([0, 1, 255], "SHA256");
            Hash third = new Hash([0, 1, 255], "SHA256");

            Assert.IsTrue(first.Equals(second));
            Assert.IsTrue(second.Equals(third));
            Assert.IsTrue(first.Equals(third));
        }

        [TestMethod]
        public void Equals_Null_ReturnsFalse()
        {
            Hash hash = new Hash([0, 1, 255], "SHA256");
            IEquatable<Hash> equatable = hash;

            Assert.IsFalse(hash.Equals((Hash?)null));
            Assert.IsFalse(hash.Equals((object?)null));
            Assert.IsFalse(equatable.Equals(null));
        }

        [TestMethod]
        public void Equals_DifferentObjectType_ReturnsFalse()
        {
            Hash hash = new Hash([0, 1, 255], "SHA256");

            Assert.IsFalse(hash.Equals(new object()));
            Assert.IsFalse(hash.Equals((object)new byte[] { 0, 1, 255 }));
            Assert.IsFalse(hash.Equals((object)"0001FF"));
        }

        [TestMethod]
        [DataRow(false, true, false)]
        [DataRow(true, false, false)]
        [DataRow(true, true, true)]
        public void EqualityOperators_NullOperands_AreComplementary(
            bool leftIsNull, bool rightIsNull, bool expectedEqual)
        {
            Hash? left = leftIsNull ? null : new Hash([0, 1, 255], "SHA256");
            Hash? right = rightIsNull ? null : new Hash([0, 1, 255], "SHA256");

            Assert.AreEqual(expectedEqual, left == right);
            Assert.AreEqual(!expectedEqual, left != right);
        }

        [TestMethod]
        [DataRow(new byte[] { })]
        [DataRow(new byte[] { 0 })]
        [DataRow(new byte[] { 0, 1, 171, 205, 239, 255 })]
        [DataRow(new byte[] { 255, 254, 128, 0 })]
        public void GetHashCode_EqualInstances_ReturnsSameStableCode(byte[] value)
        {
            Hash first = new Hash((byte[])value.Clone(), "SHA256");
            Hash second = new Hash((byte[])value.Clone(), "SHA256");
            int code = first.GetHashCode();

            Assert.IsTrue(first.Equals(second));
            Assert.AreEqual(code, second.GetHashCode());
            Assert.AreEqual(code, first.GetHashCode());
        }

        [TestMethod]
        public void HashSet_EqualValuesAndDifferentAlgorithms_UsesValueEquality()
        {
            Hash original = new Hash([0, 1, 255], "SHA256");
            Hash equal = new Hash([0, 1, 255], "SHA256");
            Hash differentName = new Hash([0, 1, 255], "SHA512");
            Hash differentValue = new Hash([0, 1, 254], "SHA256");
            HashSet<Hash> hashes = new HashSet<Hash> { original };

            Assert.IsTrue(hashes.Contains(equal));
            Assert.IsFalse(hashes.Add(equal));
            Assert.IsFalse(hashes.Contains(differentName));
            Assert.IsTrue(hashes.Add(differentName));
            Assert.IsFalse(hashes.Contains(differentValue));
            Assert.IsTrue(hashes.Add(differentValue));
            Assert.HasCount(3, hashes);
        }
    }
}
