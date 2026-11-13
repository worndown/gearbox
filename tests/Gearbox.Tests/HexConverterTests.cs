namespace Gearbox.Tests
{
    [TestClass]
    public class HexConverterTests
    {
        [TestMethod]
        public void ToHexString()
        {
            byte[] array = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

            string hexString = HexConverter.ToHexString(array);
            Assert.AreEqual("000102030405060708090A0B0C0D0E0F1011121314", hexString);

            hexString = HexConverter.ToHexString(array, 10, 7);
            Assert.AreEqual("0A0B0C0D0E0F10", hexString);

            hexString = HexConverter.ToHexString(array, 0, 5);
            Assert.AreEqual("0001020304", hexString);

            hexString = HexConverter.ToHexString(array, 16, 5);
            Assert.AreEqual("1011121314", hexString);

            array = [255, 255, 255, 16];
            hexString = HexConverter.ToHexString(array);
            Assert.AreEqual("FFFFFF10", hexString);

            hexString = HexConverter.ToHexString([]);
            Assert.AreEqual(string.Empty, hexString);
        }

        [TestMethod]
        public void ToHexString_ThrowsNullArgumentException()
        {
            Assert.Throws<ArgumentNullException>(() => HexConverter.ToHexString(null!));
            Assert.Throws<ArgumentNullException>(() => HexConverter.ToHexString(null!, 0, 0));
        }

        [TestMethod]
        public void ToEscapedHexString()
        {
            byte[] array = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

            string hexString = HexConverter.ToEscapedHexString(array, ' ');
            Assert.AreEqual("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14", hexString);

            hexString = HexConverter.ToEscapedHexString(array, 10, 7, ' ');
            Assert.AreEqual("0A 0B 0C 0D 0E 0F 10", hexString);

            hexString = HexConverter.ToEscapedHexString(array, 0, 5, ' ');
            Assert.AreEqual("00 01 02 03 04", hexString);

            hexString = HexConverter.ToEscapedHexString(array, 16, 5, ' ');
            Assert.AreEqual("10 11 12 13 14", hexString);

            array = [255, 255, 255, 16];
            hexString = HexConverter.ToEscapedHexString(array, ' ');
            Assert.AreEqual("FF FF FF 10", hexString);

            array = [255];
            hexString = HexConverter.ToEscapedHexString(array, ' ');
            Assert.AreEqual("FF", hexString);

            hexString = HexConverter.ToEscapedHexString([], ' ');
            Assert.AreEqual(string.Empty, hexString);
        }

        [TestMethod]
        public void ToByteArray()
        {
            string hexString = "000102030405060708090A0B0C0D0E0F1011121314";

            byte[] expected = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
            byte[] result = HexConverter.ToByteArray(hexString);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.SequenceEqual(expected));

            expected = [0, 1, 2, 3, 4];
            result = HexConverter.ToByteArray(hexString, 0, 10);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.SequenceEqual(expected));

            expected = [16, 17, 18, 19, 20];
            result = HexConverter.ToByteArray(hexString, 32, 10);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.SequenceEqual(expected));

            expected = [3, 4, 5, 6, 7];
            result = HexConverter.ToByteArray(hexString, 6, 10);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.SequenceEqual(expected));

            result = HexConverter.ToByteArray(string.Empty);
            Assert.IsNotNull(result);
            Assert.AreEqual(0, result.Length);
        }
    }
}
