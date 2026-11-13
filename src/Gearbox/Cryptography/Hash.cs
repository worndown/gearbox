namespace Gearbox.Cryptography
{
    /// <summary>
    /// Cryptographic hash value.
    /// </summary>
    public sealed class Hash : IEquatable<Hash>
    {
        /// <summary>
        /// Initializes a new instance of the Hash class.
        /// </summary>
        /// <param name="value">Hash value.</param>
        /// <param name="name">Hash algorithm name.</param>
        internal Hash(byte[] value, string name)
        {
            this.Value = value;
            this.Name = name;
        }

        /// <summary>
        /// Hash value.
        /// </summary>
        public byte[] Value { get; }

        /// <summary>
        /// Hash algorithm name.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Returns string representation of this object.
        /// </summary>
        /// <returns>String representation of this object.</returns>
        public override string ToString()
        {
            return HexConverter.ToHexString(this.Value);
        }

        /// <summary>
        /// Checks if this objects equals to the other.
        /// </summary>
        /// <param name="other">The other object.</param>
        /// <returns>true if objects are equal; false otherwise.</returns>
        public bool Equals(Hash? other)
        {
            if (ReferenceEquals(null, other))
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return this.Name == other.Name && this.Value.SequenceEqual(other.Value);
        }

        /// <summary>
        /// Checks if this object equals to the other.
        /// </summary>
        /// <param name="obj">The other object.</param>
        /// <returns>true if objects are equal; false otherwise.</returns>
        public override bool Equals(object? obj)
        {
            return this.Equals(obj as Hash);
        }

        /// <summary>
        /// Returns hash code for this object.
        /// </summary>
        /// <returns>Hash code value.</returns>
        public override int GetHashCode()
        {
            int hashCode = this.Value.Length;

            for (int i = 0; i < this.Value.Length; ++i)
            {
                hashCode = unchecked(hashCode * 314159 + this.Value[i]);
            }

            return hashCode;
        }

        /// <summary>
        /// Compares two hash values for equality.
        /// </summary>
        /// <param name="left">The left value.</param>
        /// <param name="right">The right value.</param>
        /// <returns>true if values are equal; false otherwise.</returns>
        public static bool operator ==(Hash? left, Hash? right)
        {
            return ReferenceEquals(left, right) || (!ReferenceEquals(null, left) && left.Equals(right));
        }

        /// <summary>
        /// Compares two hash values for inequality.
        /// </summary>
        /// <param name="left">The left value.</param>
        /// <param name="right">The right value.</param>
        /// <returns>true if values are not equal; false otherwise.</returns>
        public static bool operator !=(Hash? left, Hash? right)
        {
            return !(left == right);
        }
    }
}
