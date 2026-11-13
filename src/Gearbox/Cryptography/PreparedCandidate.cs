using System.Numerics;

namespace Gearbox.Cryptography;

internal enum PreparationOutcome { Composite, KnownPrime, NeedsRandomRounds }

// Shared by all rounds of an epoch. BigInteger values are immutable.
internal sealed record PreparedCandidate(BigInteger Candidate, BigInteger OddPart, int PowerOfTwo,
    BigInteger WitnessRange, int WitnessByteCount, byte HighByteMask);
