namespace Gearbox
{
    /// <summary>
    /// Converts between hexadecimal strings and byte arrays.
    /// </summary>
    public static class HexConverter
    {
        private const string HexDigits = "0123456789ABCDEF";

        /// <summary>
        /// Converts a hexadecimal string to a byte array.
        /// </summary>
        /// <param name="hexString">An even-length string of hexadecimal digits, in either case.</param>
        /// <returns>The resulting byte array.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="hexString"/> is null.</exception>
        /// <exception cref="FormatException">The string has an odd length or contains non-hexadecimal characters.</exception>
        public static byte[] ToByteArray(string hexString)
        {
            ArgumentNullException.ThrowIfNull(hexString);
            return Convert.FromHexString(hexString);
        }

        /// <summary>
        /// Converts a range of a hexadecimal string to a byte array.
        /// </summary>
        /// <param name="hexString">The string to convert.</param>
        /// <param name="pos">String position to start conversion from.</param>
        /// <param name="count">Number of characters to convert. Must be even.</param>
        /// <returns>The resulting byte array.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="hexString"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The position or count is outside the string.</exception>
        /// <exception cref="FormatException">The selected range has an odd length or contains non-hexadecimal characters.</exception>
        public static byte[] ToByteArray(string hexString, int pos, int count)
        {
            ArgumentNullException.ThrowIfNull(hexString);
            ArgumentOutOfRangeException.ThrowIfNegative(pos);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(pos, hexString.Length);
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(count, hexString.Length - pos);

            return Convert.FromHexString(hexString.AsSpan(pos, count));
        }

        /// <summary>
        /// Converts a byte array into an uppercase hexadecimal string.
        /// </summary>
        /// <param name="array">The byte array to convert.</param>
        /// <returns>The resulting hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="array"/> is null.</exception>
        public static string ToHexString(byte[] array)
        {
            ArgumentNullException.ThrowIfNull(array);
            return Convert.ToHexString(array);
        }

        /// <summary>
        /// Converts a range of a byte array into an uppercase hexadecimal string.
        /// </summary>
        /// <param name="array">The byte array to convert.</param>
        /// <param name="offset">Array offset to start conversion from.</param>
        /// <param name="count">Number of bytes to convert.</param>
        /// <returns>The resulting hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="array"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The offset or count is outside the array.</exception>
        public static string ToHexString(byte[] array, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(array);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, array.Length);
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(count, array.Length - offset);

            return Convert.ToHexString(array.AsSpan(offset, count));
        }

        /// <summary>
        /// Converts a byte array into uppercase hexadecimal pairs separated by a character.
        /// </summary>
        /// <param name="array">The byte array to convert.</param>
        /// <param name="escapeChar">The character to insert between pairs, with no leading or trailing separator.</param>
        /// <returns>The resulting hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="array"/> is null.</exception>
        public static string ToEscapedHexString(byte[] array, char escapeChar)
        {
            ArgumentNullException.ThrowIfNull(array);
            return ToEscapedHexString(array, 0, array.Length, escapeChar);
        }

        /// <summary>
        /// Converts a range of a byte array into uppercase hexadecimal pairs separated by a character.
        /// </summary>
        /// <param name="array">The byte array to convert.</param>
        /// <param name="offset">Array offset to start conversion from.</param>
        /// <param name="count">Number of bytes to convert.</param>
        /// <param name="escapeChar">The character to insert between pairs, with no leading or trailing separator.</param>
        /// <returns>The resulting hexadecimal string.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="array"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The offset or count is outside the array.</exception>
        /// <exception cref="OverflowException">The resulting string length exceeds <see cref="int.MaxValue"/>.</exception>
        public static string ToEscapedHexString(byte[] array, int offset, int count, char escapeChar)
        {
            ArgumentNullException.ThrowIfNull(array);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, array.Length);
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(count, array.Length - offset);

            if (count == 0)
            {
                return string.Empty;
            }

            int stringLength = checked((int)(count * 3L - 1));
            return string.Create(stringLength, (array, offset, count, escapeChar), static (characters, state) =>
            {
                int encodedIndex = 0;
                for (int i = 0; i < state.count; ++i)
                {
                    if (i > 0)
                    {
                        characters[encodedIndex++] = state.escapeChar;
                    }

                    byte value = state.array[state.offset + i];
                    characters[encodedIndex++] = HexDigits[value >> 4];
                    characters[encodedIndex++] = HexDigits[value & 0xF];
                }
            });
        }
    }
}
