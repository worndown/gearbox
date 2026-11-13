namespace Gearbox.Tests
{
    [TestClass]
    public class HexConverterTests
    {
        [TestMethod]
        [DataRow(new byte[] { }, "")]
        [DataRow(new byte[] { 0 }, "00")]
        [DataRow(new byte[] { 1, 171, 205, 239 }, "01ABCDEF")]
        [DataRow(new byte[] { 255, 255, 255, 16 }, "FFFFFF10")]
        public void ToHexString_ByteValues_ReturnsUppercaseHex(byte[] array, string expected)
        {
            Assert.AreEqual(expected, HexConverter.ToHexString(array));
        }

        [TestMethod]
        [DataRow(0, 5, "0001ABCDFF")]
        [DataRow(1, 3, "01ABCD")]
        [DataRow(0, 2, "0001")]
        [DataRow(3, 2, "CDFF")]
        [DataRow(0, 0, "")]
        [DataRow(3, 0, "")]
        [DataRow(5, 0, "")]
        public void ToHexString_ArraySlice_ConvertsOnlySelectedBytes(int offset, int count, string expected)
        {
            byte[] array = [0, 1, 171, 205, 255];
            byte[] original = (byte[])array.Clone();

            Assert.AreEqual(expected, HexConverter.ToHexString(array, offset, count));
            CollectionAssert.AreEqual(original, array);
        }

        [TestMethod]
        public void ToHexString_NullArray_ThrowsArgumentNullException()
        {
            Assert.AreEqual("array", Assert.ThrowsExactly<ArgumentNullException>(() => HexConverter.ToHexString(null!)).ParamName);
            Assert.AreEqual("array", Assert.ThrowsExactly<ArgumentNullException>(() => HexConverter.ToHexString(null!, 0, 0)).ParamName);
            Assert.AreEqual("array", Assert.ThrowsExactly<ArgumentNullException>(() => HexConverter.ToHexString(null!, 0, 1)).ParamName);
        }

        [TestMethod]
        [DataRow(-1, 0, "offset")]
        [DataRow(int.MinValue, 1, "offset")]
        [DataRow(6, 0, "offset")]
        [DataRow(int.MaxValue, 1, "offset")]
        [DataRow(int.MaxValue, int.MaxValue, "offset")]
        [DataRow(0, -1, "count")]
        [DataRow(0, int.MinValue, "count")]
        [DataRow(0, 6, "count")]
        [DataRow(5, 1, "count")]
        [DataRow(4, 2, "count")]
        [DataRow(1, int.MaxValue, "count")]
        public void ToHexString_InvalidRange_ThrowsArgumentOutOfRangeException(int offset, int count, string parameterName)
        {
            ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => HexConverter.ToHexString(new byte[5], offset, count));

            Assert.AreEqual(parameterName, exception.ParamName);
        }

        [TestMethod]
        [DataRow(new byte[] { }, "")]
        [DataRow(new byte[] { 255 }, "FF")]
        [DataRow(new byte[] { 0, 1, 171, 205, 239 }, "00 01 AB CD EF")]
        [DataRow(new byte[] { 255, 255, 255, 16 }, "FF FF FF 10")]
        public void ToEscapedHexString_ByteValues_ReturnsSeparatedUppercaseHex(byte[] array, string expected)
        {
            Assert.AreEqual(expected, HexConverter.ToEscapedHexString(array, ' '));
        }

        [TestMethod]
        [DataRow(0, 5, "00:01:AB:CD:FF")]
        [DataRow(1, 3, "01:AB:CD")]
        [DataRow(0, 2, "00:01")]
        [DataRow(3, 2, "CD:FF")]
        [DataRow(2, 1, "AB")]
        [DataRow(0, 0, "")]
        [DataRow(3, 0, "")]
        [DataRow(5, 0, "")]
        public void ToEscapedHexString_ArraySlice_ConvertsOnlySelectedBytes(int offset, int count, string expected)
        {
            byte[] array = [0, 1, 171, 205, 255];
            byte[] original = (byte[])array.Clone();

            Assert.AreEqual(expected, HexConverter.ToEscapedHexString(array, offset, count, ':'));
            CollectionAssert.AreEqual(original, array);
        }

        [TestMethod]
        [DataRow(' ', "01 AB FF")]
        [DataRow('-', "01-AB-FF")]
        [DataRow('\0', "01\0AB\0FF")]
        [DataRow('\u00E9', "01\u00E9AB\u00E9FF")]
        [DataRow('\u0100', "01\u0100AB\u0100FF")]
        [DataRow('\u20AC', "01\u20ACAB\u20ACFF")]
        [DataRow('\uFFFF', "01\uFFFFAB\uFFFFFF")]
        public void ToEscapedHexString_SeparatorCharacters_PreservesCharacterBetweenBytes(char escapeChar, string expected)
        {
            Assert.AreEqual(expected, HexConverter.ToEscapedHexString([1, 171, 255], escapeChar));
            Assert.AreEqual(expected, HexConverter.ToEscapedHexString([0, 1, 171, 255, 0], 1, 3, escapeChar));
        }

        [TestMethod]
        public void ToEscapedHexString_AllByteValues_MatchesNumericFormatting()
        {
            byte[] array = Enumerable.Range(0, 256).Select(value => (byte)value).ToArray();
            string expected = string.Join('\u20AC', array.Select(value => value.ToString("X2")));

            Assert.AreEqual(expected, HexConverter.ToEscapedHexString(array, '\u20AC'));
        }

        [TestMethod]
        public void ToEscapedHexString_NullArray_ThrowsArgumentNullException()
        {
            Assert.AreEqual("array", Assert.ThrowsExactly<ArgumentNullException>(() => HexConverter.ToEscapedHexString(null!, ' ')).ParamName);
            Assert.AreEqual("array", Assert.ThrowsExactly<ArgumentNullException>(() => HexConverter.ToEscapedHexString(null!, 0, 0, ' ')).ParamName);
            Assert.AreEqual("array", Assert.ThrowsExactly<ArgumentNullException>(() => HexConverter.ToEscapedHexString(null!, 0, 1, ' ')).ParamName);
        }

        [TestMethod]
        [DataRow(-1, 0, "offset")]
        [DataRow(int.MinValue, 1, "offset")]
        [DataRow(6, 0, "offset")]
        [DataRow(int.MaxValue, 1, "offset")]
        [DataRow(int.MaxValue, int.MaxValue, "offset")]
        [DataRow(0, -1, "count")]
        [DataRow(0, int.MinValue, "count")]
        [DataRow(0, 6, "count")]
        [DataRow(5, 1, "count")]
        [DataRow(4, 2, "count")]
        [DataRow(1, int.MaxValue, "count")]
        public void ToEscapedHexString_InvalidRange_ThrowsArgumentOutOfRangeException(int offset, int count, string parameterName)
        {
            ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => HexConverter.ToEscapedHexString(new byte[5], offset, count, ' '));

            Assert.AreEqual(parameterName, exception.ParamName);
        }

        [TestMethod]
        [DataRow("", new byte[] { })]
        [DataRow("00", new byte[] { 0 })]
        [DataRow("0123456789abcdef", new byte[] { 1, 35, 69, 103, 137, 171, 205, 239 })]
        [DataRow("aBcDeF", new byte[] { 171, 205, 239 })]
        [DataRow("FFFFFF10", new byte[] { 255, 255, 255, 16 })]
        public void ToByteArray_HexString_ReturnsBytes(string hexString, byte[] expected)
        {
            CollectionAssert.AreEqual(expected, HexConverter.ToByteArray(hexString));
        }

        [TestMethod]
        [DataRow("0001ABCDFF", 0, 10, new byte[] { 0, 1, 171, 205, 255 })]
        [DataRow("0001ABCDFF", 2, 6, new byte[] { 1, 171, 205 })]
        [DataRow("0001ABCDFF", 0, 4, new byte[] { 0, 1 })]
        [DataRow("0001ABCDFF", 6, 4, new byte[] { 205, 255 })]
        [DataRow("x00aBff!", 1, 6, new byte[] { 0, 171, 255 })]
        [DataRow("invalidAB??", 7, 2, new byte[] { 171 })]
        [DataRow("", 0, 0, new byte[] { })]
        [DataRow("invalid", 0, 0, new byte[] { })]
        [DataRow("invalid", 3, 0, new byte[] { })]
        [DataRow("invalid", 7, 0, new byte[] { })]
        public void ToByteArray_StringSlice_ConvertsOnlySelectedCharacters(string hexString, int pos, int count, byte[] expected)
        {
            CollectionAssert.AreEqual(expected, HexConverter.ToByteArray(hexString, pos, count));
        }

        [TestMethod]
        public void ToByteArray_NullString_ThrowsArgumentNullException()
        {
            Assert.AreEqual("hexString", Assert.ThrowsExactly<ArgumentNullException>(() => HexConverter.ToByteArray(null!)).ParamName);
            Assert.AreEqual("hexString", Assert.ThrowsExactly<ArgumentNullException>(() => HexConverter.ToByteArray(null!, 0, 0)).ParamName);
            Assert.AreEqual("hexString", Assert.ThrowsExactly<ArgumentNullException>(() => HexConverter.ToByteArray(null!, 0, 2)).ParamName);
        }

        [TestMethod]
        [DataRow(-1, 0, "pos")]
        [DataRow(int.MinValue, 2, "pos")]
        [DataRow(5, 0, "pos")]
        [DataRow(int.MaxValue, 2, "pos")]
        [DataRow(int.MaxValue, int.MaxValue, "pos")]
        [DataRow(0, -1, "count")]
        [DataRow(0, int.MinValue, "count")]
        [DataRow(0, 5, "count")]
        [DataRow(4, 2, "count")]
        [DataRow(3, 2, "count")]
        [DataRow(2, int.MaxValue, "count")]
        public void ToByteArray_InvalidRange_ThrowsArgumentOutOfRangeException(int pos, int count, string parameterName)
        {
            ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => HexConverter.ToByteArray("00AB", pos, count));

            Assert.AreEqual(parameterName, exception.ParamName);
        }

        [TestMethod]
        [DataRow("0")]
        [DataRow("ABC")]
        [DataRow("12345")]
        public void ToByteArray_OddLength_ThrowsFormatException(string hexString)
        {
            Assert.ThrowsExactly<FormatException>(() => HexConverter.ToByteArray(hexString));
            Assert.ThrowsExactly<FormatException>(() => HexConverter.ToByteArray("x" + hexString + "!", 1, hexString.Length));
        }

        [TestMethod]
        [DataRow("0G")]
        [DataRow("G0")]
        [DataRow("0/")]
        [DataRow("0:")]
        [DataRow("0@")]
        [DataRow("0`")]
        [DataRow("0g")]
        [DataRow("-1")]
        [DataRow("+1")]
        [DataRow(" 0")]
        [DataRow("0 ")]
        [DataRow("\t0")]
        [DataRow("0\n")]
        [DataRow("0\0")]
        [DataRow("\u00800")]
        [DataRow("0\u00E9")]
        [DataRow("\uFF100")]
        [DataRow("0\uFFFF")]
        [DataRow("0x01")]
        [DataRow("00ABFF0G")]
        public void ToByteArray_InvalidCharacters_ThrowsFormatException(string hexString)
        {
            Assert.ThrowsExactly<FormatException>(() => HexConverter.ToByteArray(hexString));
            Assert.ThrowsExactly<FormatException>(() => HexConverter.ToByteArray("x" + hexString + "!", 1, hexString.Length));
        }

        [TestMethod]
        public void ToHexString_AllByteValues_ReturnsKnownHexAndRoundTrips()
        {
            const string expected =
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
                "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F" +
                "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F" +
                "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F" +
                "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F" +
                "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
                "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF" +
                "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
            byte[] array = Enumerable.Range(0, 256).Select(value => (byte)value).ToArray();

            Assert.AreEqual(expected, HexConverter.ToHexString(array));
            CollectionAssert.AreEqual(array, HexConverter.ToByteArray(expected));
            CollectionAssert.AreEqual(array, HexConverter.ToByteArray(expected.ToLowerInvariant()));
        }
    }
}
