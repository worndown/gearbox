using System.Globalization;

namespace Gearbox.Tests
{
    [TestClass]
    public class WildcardTests
    {
        [TestMethod]
        public void IsMatch_LiteralPattern_MatchesEntireInputIgnoringCase()
        {
            Wildcard wildcard = new Wildcard("xyz");
            Assert.IsTrue(wildcard.IsMatch("xyz"));
            Assert.IsTrue(wildcard.IsMatch("XYZ"));
            Assert.IsFalse(wildcard.IsMatch(""));
            Assert.IsFalse(wildcard.IsMatch("xy"));
            Assert.IsFalse(wildcard.IsMatch("axyz"));
            Assert.IsFalse(wildcard.IsMatch("xyza"));
        }

        [TestMethod]
        [DataRow("?bc?", "abcd", true)]
        [DataRow("?bc?", "abxd", false)]
        [DataRow("?bc?", "abc", false)]
        [DataRow("?bc?", "abcde", false)]
        [DataRow("?", "", false)]
        [DataRow("?", "\n", true)]
        [DataRow("?", "\r\n", false)]
        [DataRow("a?b", "a\nb", true)]
        public void IsMatch_QuestionMark_MatchesExactlyOneCharacter(string pattern, string input, bool expected)
        {
            Assert.AreEqual(expected, new Wildcard(pattern).IsMatch(input));
        }

        [TestMethod]
        [DataRow("*", "", true)]
        [DataRow("*", "a\r\nb", true)]
        [DataRow("a*b", "ab", true)]
        [DataRow("a*b", "a\r\nb", true)]
        public void IsMatch_Star_MatchesZeroOrMoreCharacters(string pattern, string input, bool expected)
        {
            Assert.AreEqual(expected, new Wildcard(pattern).IsMatch(input));
        }

        [TestMethod]
        public void IsMatch_CharacterSet_MatchesExactlyOneMember()
        {
            Wildcard wildcard = new Wildcard("aaa[bcd]zzz");
            Assert.IsTrue(wildcard.IsMatch("aaabzzz"));
            Assert.IsTrue(wildcard.IsMatch("aaaczzz"));
            Assert.IsTrue(wildcard.IsMatch("aaadzzz"));
            Assert.IsTrue(wildcard.IsMatch("aaaBzzz"));
            Assert.IsFalse(wildcard.IsMatch("aaaezzz"));
            Assert.IsFalse(wildcard.IsMatch("aaabczzz"));
            Assert.IsFalse(wildcard.IsMatch("aaazzz"));
        }

        [TestMethod]
        public void IsMatch_CharacterRange_MatchesInclusiveBoundsAndInterior()
        {
            Wildcard wildcard = new Wildcard("aaa[0-9]zzz");
            Assert.IsTrue(wildcard.IsMatch("aaa0zzz"));
            Assert.IsTrue(wildcard.IsMatch("aaa5zzz"));
            Assert.IsTrue(wildcard.IsMatch("aaa9zzz"));
            Assert.IsFalse(wildcard.IsMatch("aaaxzzz"));
            Assert.IsFalse(wildcard.IsMatch("aaa10zzz"));
        }

        [TestMethod]
        [DataRow("a{2}", "a{2}", true)]
        [DataRow("a{2}", "aa", false)]
        [DataRow("a{2,3}", "a{2,3}", true)]
        [DataRow("a{2,3}", "aaa", false)]
        [DataRow("a{2,}", "a{2,}", true)]
        [DataRow("a{2,}", "aaaa", false)]
        [DataRow("{2}", "{2}", true)]
        [DataRow("a}b", "a}b", true)]
        [DataRow("a{b", "a{b", true)]
        [DataRow("a.b", "a.b", true)]
        [DataRow("a.b", "axb", false)]
        [DataRow("a+b", "a+b", true)]
        [DataRow("a+b", "aaab", false)]
        [DataRow("a|b", "a|b", true)]
        [DataRow("a|b", "a", false)]
        [DataRow("(ab)", "(ab)", true)]
        [DataRow("(ab)", "ab", false)]
        [DataRow("^ab$", "^ab$", true)]
        [DataRow("^ab$", "ab", false)]
        [DataRow(@"a\b", @"a\b", true)]
        [DataRow(@"a\b", "ab", false)]
        [DataRow("a]b", "a]b", true)]
        [DataRow("file{2}*.txt", "file{2}x.txt", true)]
        [DataRow("file{2}*.txt", "fileex.txt", false)]
        public void IsMatch_RegexMetacharacters_TreatsAsLiterals(string pattern, string input, bool expected)
        {
            Assert.AreEqual(expected, new Wildcard(pattern).IsMatch(input));
        }

        [TestMethod]
        [DataRow("xyz", "xyz\n", false)]
        [DataRow("xyz", "xyz\r\n", false)]
        [DataRow("xyz", "\nxyz", false)]
        [DataRow("xyz\n", "xyz\n", true)]
        [DataRow("xyz\n", "xyz\n\n", false)]
        [DataRow("a*b", "ab\n", false)]
        [DataRow(" a ", " a ", true)]
        [DataRow(" a ", "a", false)]
        public void IsMatch_NewlinesAndWhitespace_RequiresEntireInput(string pattern, string input, bool expected)
        {
            Assert.AreEqual(expected, new Wildcard(pattern).IsMatch(input));
        }

        [TestMethod]
        [DataRow(@"[\d]", @"\", true)]
        [DataRow(@"[\d]", "d", true)]
        [DataRow(@"[\d]", "5", false)]
        [DataRow(@"[\]", @"\", true)]
        [DataRow(@"[\]", "x", false)]
        [DataRow(@"[\n]", "n", true)]
        [DataRow(@"[\n]", "\n", false)]
        [DataRow("[*?]", "*", true)]
        [DataRow("[*?]", "?", true)]
        [DataRow("[*?]", ".", false)]
        [DataRow("[{}()$^.+|]", "^", true)]
        [DataRow("[{}()$^.+|]", "{", true)]
        [DataRow("[[]", "[", true)]
        [DataRow("[]*?]", "]", true)]
        [DataRow("[]*?]", "*", true)]
        [DataRow("[]*?]", "?", true)]
        [DataRow("[]*?]", ".", false)]
        [DataRow("[]*?]", "**", false)]
        [DataRow("[-a]", "-", true)]
        [DataRow("[a-]", "-", true)]
        [DataRow("[a-cx-z]", "B", true)]
        [DataRow("[a-cx-z]", "Y", true)]
        [DataRow("[a-cx-z]", "d", false)]
        [DataRow("[a-c][0-9]", "B5", true)]
        [DataRow("[a-c][0-9]", "D5", false)]
        [DataRow("[^ab]", "c", true)]
        [DataRow("[^ab]", "A", false)]
        [DataRow(@"[^\]", @"\", false)]
        [DataRow(@"[^\]", "x", true)]
        [DataRow("[^]a]", "]", false)]
        [DataRow("[^]a]", "x", true)]
        public void IsMatch_CharacterGroups_PreservesLiteralsRangesAndNegation(string pattern, string input, bool expected)
        {
            Assert.AreEqual(expected, new Wildcard(pattern).IsMatch(input));
        }

        [TestMethod]
        [DataRow("**", "", true)]
        [DataRow("aaa*bbb*ccc", "aaxbbbxccc", false)]
        [DataRow("*ab*bc", "abc", false)]
        [DataRow("*ab*bc", "abbc", true)]
        [DataRow("*ab*bc", "xabxabxbc", true)]
        [DataRow("*a?*?b", "axb", false)]
        [DataRow("*a?*?b", "axxb", true)]
        [DataRow("*a*b", "aab", true)]
        [DataRow("*a*b", "aba", false)]
        [DataRow("a**b***c", "abc", true)]
        [DataRow("a**b***c", "axbyc", true)]
        [DataRow("*a*", "baab", true)]
        [DataRow("*[a-c]?*z", "xxB\nyz", true)]
        [DataRow("*[*]*[?]", "x*y?", true)]
        [DataRow("*{2}*b", "a{2}xb", true)]
        public void IsMatch_MultipleWildcards_MatchesSeparateSegments(string pattern, string input, bool expected)
        {
            Assert.AreEqual(expected, new Wildcard(pattern).IsMatch(input));
        }

        [TestMethod]
        [Timeout(10000)]
        public void IsMatch_RepeatedStars_CompletesWithExpectedResult()
        {
            Wildcard wildcard = new Wildcard(string.Concat(Enumerable.Repeat("*a", 20)) + "b");
            string input = new string('a', 30);

            Assert.IsFalse(wildcard.IsMatch(input));
            Assert.IsTrue(wildcard.IsMatch(input + "b"));
            Assert.IsFalse(wildcard.IsMatch(new string('a', 19) + "b"));
        }

        [TestMethod]
        public void IsMatch_LongPattern_ReturnsExpectedResult()
        {
            string literal = new string('a', 4096);
            Wildcard wildcard = new Wildcard(literal + "*b");

            Assert.IsTrue(wildcard.IsMatch(literal + "b"));
            Assert.IsTrue(wildcard.IsMatch(literal.ToUpperInvariant() + "xyzb"));
            Assert.IsFalse(wildcard.IsMatch(literal + "c"));
        }

        [TestMethod]
        [DoNotParallelize]
        public void IsMatch_DifferentCultures_UsesInvariantCaseRules()
        {
            CultureInfo originalCulture = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
                Wildcard english = new Wildcard("I");
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
                Wildcard turkish = new Wildcard("i");
                Wildcard range = new Wildcard("[A-Z]");

                foreach (string culture in new[] { "en-US", "tr-TR" })
                {
                    CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                    foreach (string input in new[] { "I", "i" })
                    {
                        Assert.IsTrue(english.IsMatch(input));
                        Assert.IsTrue(turkish.IsMatch(input));
                        Assert.IsTrue(range.IsMatch(input));
                    }

                    Assert.IsFalse(english.IsMatch("\u0130"));
                    Assert.IsFalse(turkish.IsMatch("\u0131"));
                }

                Assert.IsTrue(english.Equals(turkish));
                Assert.AreEqual(english.GetHashCode(), turkish.GetHashCode());
            }
            finally
            {
                CultureInfo.CurrentCulture = originalCulture;
            }
        }

        [TestMethod]
        public void Constructor_NullOrEmptyPattern_ThrowsArgumentException()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new Wildcard(null!));
            Assert.ThrowsExactly<ArgumentException>(() => new Wildcard(""));
        }

        [TestMethod]
        public void IsMatch_NullInput_ThrowsArgumentNullException()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new Wildcard("*").IsMatch(null!));
        }

        [TestMethod]
        [DataRow("[")]
        [DataRow("[]")]
        [DataRow("[^]")]
        [DataRow("[abc")]
        [DataRow("[z-a]")]
        public void Constructor_InvalidCharacterGroups_ThrowsArgumentException(string pattern)
        {
            Assert.Throws<ArgumentException>(() => new Wildcard(pattern));
        }

        [TestMethod]
        [DataRow("xyz", "XYZ", true)]
        [DataRow("[a-z]*", "[A-Z]*", true)]
        [DataRow("xyz", "xy", false)]
        [DataRow("a*", "a?", false)]
        public void Equals_OriginalPatterns_ComparesIgnoringCase(string pattern, string otherPattern, bool expected)
        {
            Wildcard wildcard = new Wildcard(pattern);
            Wildcard other = new Wildcard(otherPattern);

            Assert.AreEqual(expected, wildcard.Equals(other));
            Assert.AreEqual(expected, other.Equals(wildcard));
        }

        [TestMethod]
        public void Equals_SameInstance_ReturnsTrue()
        {
            Wildcard wildcard = new Wildcard("xyz");
            Assert.IsTrue(wildcard.Equals(wildcard));
        }

        [TestMethod]
        public void Equals_NullOrDifferentType_ReturnsFalse()
        {
            Wildcard wildcard = new Wildcard("xyz");
            Assert.IsFalse(wildcard.Equals(null));
            Assert.IsFalse(wildcard.Equals("xyz"));
        }

        [TestMethod]
        [DataRow("xyz", "XYZ")]
        [DataRow("[a-z]*", "[A-Z]*")]
        public void GetHashCode_EqualPatterns_ReturnsSameHashCode(string pattern, string otherPattern)
        {
            Assert.AreEqual(new Wildcard(pattern).GetHashCode(), new Wildcard(otherPattern).GetHashCode());
        }

        [TestMethod]
        public void ToString_OriginalPattern_ReturnsUnchangedPattern()
        {
            const string pattern = "Ab[0-9]*?.txt";
            Assert.AreEqual(pattern, new Wildcard(pattern).ToString());
        }
    }
}
