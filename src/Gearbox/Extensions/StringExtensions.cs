namespace Gearbox.Extensions
{
    /// <summary>
    /// String extension methods.
    /// </summary>
    public static class StringExtensions
    {
        extension(string str)
        {
            /// <summary>
            /// Truncates a string to at most the specified length.
            /// </summary>
            /// <param name="length">
            /// Maximum length in UTF-16 code units, including the ellipsis.
            /// Must be greater than 3 when using an ellipsis, or greater than 0 otherwise.
            /// </param>
            /// <param name="ellipsis">Append "..." when the string is truncated.</param>
            /// <returns>The original string if it fits; otherwise, a string of the requested length.</returns>
            /// <exception cref="ArgumentNullException">The string is null.</exception>
            /// <exception cref="ArgumentOutOfRangeException">The length is below the required minimum.</exception>
            public string Truncate(int length, bool ellipsis = true)
            {
                ArgumentNullException.ThrowIfNull(str);
                ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(length, ellipsis ? 3 : 0);

                if (str.Length <= length)
                {
                    return str;
                }

                return ellipsis ? $"{str[..(length - 3)]}..." : str[..length];
            }
        }
    }
}
