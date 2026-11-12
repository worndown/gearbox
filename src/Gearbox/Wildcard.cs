using System.Text;
using System.Text.RegularExpressions;

namespace Gearbox
{
    /// <summary>
    /// Class to perform culture-invariant, case-insensitive wildcard string matching.
    /// The pattern can contain following special characters:
    ///
    /// ?   Matches any character at the specified position.
    /// *   Matches zero or more characters, starting at the specified position.
    /// []  Matches the specified set or range of characters. A leading ^ negates the set.
    ///
    /// Backslashes are literal, including inside character sets.
    /// A literal ] must be first in its set, after an optional ^.
    /// </summary>
    public sealed class Wildcard
    {
        /// <summary>
        /// Special regex characters that should be escaped.
        /// </summary>
        private static readonly char[] RegexSpecialChars = ['[', '\\', '^', '$', '.', '|', '?', '*', '+', '(', ')', '{', '}'];

        /// <summary>
        /// Original pattern.
        /// </summary>
        private readonly string pattern;

        /// <summary>
        /// Regular expression.
        /// </summary>
        private readonly Regex regex;

        /// <summary>
        /// Initializes a new instance of the Wildcard class.
        /// </summary>
        /// <param name="pattern">Wildcard pattern.</param>
        public Wildcard(string pattern)
        {
            ArgumentException.ThrowIfNullOrEmpty(pattern);
            this.pattern = pattern;
            this.regex = Wildcard.PatternToRegex(pattern);
        }

        /// <summary>
        /// Determines if string matches the pattern.
        /// </summary>
        /// <param name="input">Input string to match.</param>
        /// <returns>true if input string matches the pattern; false otherwise.</returns>
        public bool IsMatch(string input)
        {
            return this.regex.IsMatch(input);
        }

        #region Overrides

        /// <summary>
        /// Returns a string that represents the current object.
        /// </summary>
        /// <returns>String representing current object.</returns>
        public override string ToString()
        {
            return this.pattern;
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="obj">Object to compare to the current object.</param>
        /// <returns>true if other object equals to the current object; false otherwise.</returns>
        public override bool Equals(object? obj)
        {
            return obj is Wildcard other &&
                   this.pattern.Equals(other.pattern, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Returns a hashcode for the current object.
        /// </summary>
        /// <returns>A hash code for the current object.</returns>
        public override int GetHashCode()
        {
            return this.pattern.GetHashCode(StringComparison.OrdinalIgnoreCase);
        }

        #endregion

        /// <summary>
        /// Converts a globbing pattern to a regular expression.
        /// </summary>
        /// <param name="pattern">String containing a globbing pattern.</param>
        /// <returns>Regular expression object.</returns>
        private static Regex PatternToRegex(string pattern)
        {
            List<string> segments = new List<string>();
            StringBuilder segment = new StringBuilder();
            bool characterGroup = false;
            bool firstGroupCharacter = false;
            bool groupNegationAllowed = false;

            foreach (char c in pattern)
            {
                if (characterGroup)
                {
                    if (c == ']' && !firstGroupCharacter)
                    {
                        characterGroup = false;
                    }

                    if (c == '\\' || c == '[')
                    {
                        segment.Append('\\');
                    }

                    segment.Append(c);
                    if (c != '^' || !groupNegationAllowed)
                    {
                        firstGroupCharacter = false;
                    }

                    groupNegationAllowed = false;
                    continue;
                }

                switch (c)
                {
                    case '*':
                        // Consecutive stars are equivalent to a single star.
                        if (segment.Length > 0 || segments.Count == 0)
                        {
                            segments.Add(segment.ToString());
                            segment.Clear();
                        }

                        break;
                    case '?':
                        segment.Append('.');
                        break;
                    case '[':
                        characterGroup = true;
                        firstGroupCharacter = true;
                        groupNegationAllowed = true;
                        segment.Append(c);
                        break;
                    default:
                        if (RegexSpecialChars.Contains(c))
                        {
                            segment.Append('\\');
                        }

                        segment.Append(c);
                        break;
                }
            }

            segments.Add(segment.ToString());
            StringBuilder regex = new StringBuilder();
            regex.Append("\\A").Append(segments[0]);
            for (int i = 1; i < segments.Count; i++)
            {
                if (i == segments.Count - 1)
                {
                    regex.Append(".*").Append(segments[i]);
                }
                else
                {
                    // Between stars, the earliest match leaves the most input for the
                    // remaining pattern. Atomic groups prevent exponential backtracking.
                    regex.Append("(?>.*?").Append(segments[i]).Append(')');
                }
            }

            regex.Append("\\z");
            return new Regex(
                regex.ToString(),
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline | RegexOptions.Compiled);
        }
    }
}
