using Gearbox.Extensions;

namespace Gearbox.Tests
{
    [TestClass]
    public class StringExtensionsTests
    {
        [TestMethod]
        [DataRow("abcdefgh", 6, "abc...")]
        [DataRow("abcdefgh", 4, "a...")]
        public void Truncate_DefaultOptions_IncludesEllipsisInLength(string input, int length, string expected)
        {
            Assert.AreEqual(expected, input.Truncate(length));
        }

        [TestMethod]
        [DataRow("abcdefgh", 6, true, "abc...")]
        [DataRow("abcdefgh", 4, true, "a...")]
        [DataRow("abcdefgh", 6, false, "abcdef")]
        [DataRow("abcdefgh", 3, false, "abc")]
        [DataRow("abcdefgh", 1, false, "a")]
        [DataRow("a\r\nbcdef", 6, true, "a\r\n...")]
        [DataRow("a\r\nbcdef", 3, false, "a\r\n")]
        [DataRow("  abcdef", 5, true, "  ...")]
        [DataRow("  abcdef", 2, false, "  ")]
        public void Truncate_LongerInput_ReturnsExpectedPrefix(string input, int length, bool ellipsis, string expected)
        {
            string result = input.Truncate(length, ellipsis);

            Assert.AreEqual(expected, result);
            Assert.AreEqual(length, result.Length);
        }

        [TestMethod]
        [DataRow("", 4, true)]
        [DataRow("", 1, false)]
        [DataRow("abc", 4, true)]
        [DataRow("abc", 4, false)]
        [DataRow("abcd", 4, true)]
        [DataRow("a", 1, false)]
        [DataRow("abcdefgh", int.MaxValue, true)]
        [DataRow("abcdefgh", int.MaxValue, false)]
        public void Truncate_InputFits_ReturnsOriginalInstance(string input, int length, bool ellipsis)
        {
            Assert.AreSame(input, input.Truncate(length, ellipsis));
        }

        [TestMethod]
        [DataRow(int.MinValue, true)]
        [DataRow(-1, true)]
        [DataRow(0, true)]
        [DataRow(1, true)]
        [DataRow(2, true)]
        [DataRow(3, true)]
        [DataRow(int.MinValue, false)]
        [DataRow(-1, false)]
        [DataRow(0, false)]
        public void Truncate_InvalidLength_ThrowsArgumentOutOfRangeException(int length, bool ellipsis)
        {
            ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => "abcdefgh".Truncate(length, ellipsis));

            Assert.AreEqual("length", exception.ParamName);
            Assert.AreEqual(length, exception.ActualValue);
        }

        [TestMethod]
        [DataRow("", 3, true)]
        [DataRow("abc", 3, true)]
        [DataRow("", 0, false)]
        public void Truncate_InvalidLengthWithInputThatFits_StillThrows(string input, int length, bool ellipsis)
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => input.Truncate(length, ellipsis));
        }

        [TestMethod]
        [DataRow(4, true)]
        [DataRow(1, false)]
        [DataRow(0, true)]
        [DataRow(0, false)]
        public void Truncate_NullInput_ThrowsArgumentNullException(int length, bool ellipsis)
        {
            string input = null!;
            ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
                () => input.Truncate(length, ellipsis));

            Assert.AreEqual("str", exception.ParamName);
        }
    }
}
