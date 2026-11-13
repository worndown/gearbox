using System.Runtime.CompilerServices;
using System.Text;

namespace Gearbox
{
    /// <summary>
    /// Converts between hexadecimal string to byte array and the other way around.
    /// </summary>
    public static class HexConverter
    {
        /// <summary>
        /// Nibble to hex character lookup.
        /// </summary>
        private static readonly byte[] NibbleToHex = Encoding.ASCII.GetBytes("0123456789ABCDEF");

        /// <summary>
        /// Lookup table for converting ASCII character to the actual hex value.
        /// </summary>
        private static readonly byte[] AsciiToHexMap =
        [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ];

        /// <summary>
        /// Converts the hex string to a binary array.
        /// </summary>
        /// <param name="hexString">Hex string to convert.</param>
        /// <returns>A byte[] containing the hex bytes.</returns>
        public static byte[] ToByteArray(string hexString)
        {
            return ToByteArray(hexString, 0, hexString.Length);
        }

        /// <summary>
        /// Converts a hex string to a byte array.
        /// </summary>
        /// <param name="hexString">Hex string to convert.</param>
        /// <param name="pos">String position to start conversion from.</param>
        /// <param name="count">Number of characters to convert.</param>
        /// <returns>The resulting byte array.</returns>
        public static byte[] ToByteArray(string hexString, int pos, int count)
        {
            if (count == 0)
            {
                return [];
            }

            if (count % 2 != 0)
            {
                throw new FormatException("Invalid hexadecimal string.");
            }

            int arrayLength = count / 2;
            byte[] array = new byte[arrayLength];

            for (int i = 0; i < arrayLength; ++i)
            {
                array[i] = ByteFromHexPair(hexString[pos++], hexString[pos++]);
            }

            return array;
        }

        /// <summary>
        /// Converts a byte array into a hex string.
        /// </summary>
        /// <param name="array">The byte array to convert.</param>
        /// <returns>The resulting hex string.</returns>
        public static string ToHexString(byte[] array)
        {
            return ToHexString(array, 0, array?.Length ?? 0);
        }

        /// <summary>
        /// Converts a byte array into a hex string.
        /// </summary>
        /// <param name="array">The byte array to convert.</param>
        /// <param name="offset">Array offset to start conversion from.</param>
        /// <param name="count">Number of bytes to convert.</param>
        /// <returns>The resulting hex string.</returns>
        public static string ToHexString(byte[] array, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(array);

            if (count == 0)
            {
                return string.Empty;
            }

            byte[] encodedData = new byte[count * 2];
            int encodedIndex = 0;

            for (int i = offset; i < offset + count; ++i)
            {
                encodedData[encodedIndex++] = NibbleToHex[array[i] >> 4];
                encodedData[encodedIndex++] = NibbleToHex[array[i] & 0xF];
            }

            return Encoding.ASCII.GetString(encodedData, 0, encodedData.Length);
        }

        /// <summary>
        /// Converts a byte array into escaped hex string.
        /// </summary>
        /// <param name="array">The byte array to convert.</param>
        /// <param name="escapeChar">The escape character to use.</param>
        /// <returns>The resulting hex string.</returns>
        public static string ToEscapedHexString(byte[] array, char escapeChar)
        {
            return ToEscapedHexString(array, 0, array?.Length ?? 0, escapeChar);
        }

        /// <summary>
        /// Converts a byte array into escaped hex string.
        /// </summary>
        /// <param name="array">The byte array to convert.</param>
        /// <param name="offset">Array offset to start conversion from.</param>
        /// <param name="count">Number of bytes to convert.</param>
        /// <param name="escapeChar">The escape character to use.</param>
        /// <returns>The resulting escaped hex string.</returns>
        public static string ToEscapedHexString(byte[] array, int offset, int count, char escapeChar)
        {
            if (count == 0)
            {
                return string.Empty;
            }

            byte[] encodedData = new byte[count * 3 - 1];
            int encodedIndex = 0;

            for (int i = offset; i < offset + count; ++i)
            {
                if (encodedIndex > 0)
                {
                    encodedData[encodedIndex++] = (byte)escapeChar;
                }

                encodedData[encodedIndex++] = NibbleToHex[array[i] >> 4];
                encodedData[encodedIndex++] = NibbleToHex[array[i] & 0xF];
            }

            return Encoding.ASCII.GetString(encodedData, 0, encodedData.Length);
        }

        /// <summary>
        /// Converts hex character pair into a corresponding byte value.
        /// </summary>
        /// <param name="firstChar">The first hex character.</param>
        /// <param name="secondChar">The second hex character.</param>
        /// <returns>The byte value.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte ByteFromHexPair(char firstChar, char secondChar)
        {
            byte b1 = ByteFromHexChar(firstChar);
            byte b2 = ByteFromHexChar(secondChar);
            return (byte)((b1 << 4) | b2);
        }

        /// <summary>
        /// Converts hex character into its byte value.
        /// </summary>
        /// <param name="ch">The hex character.</param>
        /// <returns>The byte value.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte ByteFromHexChar(char ch)
        {
            // Make sure resulting character is within ASCII range
            byte result = ch < 128 ? AsciiToHexMap[ch] : (byte)0xFF;
            return result != 0xFF
                ? result
                : throw new FormatException("Invalid hexadecimal string.");
        }
    }
}
