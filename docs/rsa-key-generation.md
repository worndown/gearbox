# RSA key loading and generation

Use `System.Security.Cryptography.RSA` directly to load keys and perform
cryptographic operations. `Gearbox.Cryptography.RSAKeyGenerator` offers custom
generation through Gearbox's `Prime` implementation and returns a platform `RSA`
instance. `Gearbox.Cryptography.RSAKey` is a static class containing parameter
derivation and PEM serialization helpers.

## Loading existing keys

Create a platform provider with `RSA.Create()`, then import the desired key.
Dispose the instance when finished.

For an unencrypted PEM file:

```csharp
using System.Security.Cryptography;

string pem = File.ReadAllText("private-key.pem");
using RSA existing = RSA.Create();
existing.ImportFromPem(pem);
```

`ImportFromPem` accepts PKCS#1 RSA private/public keys, PKCS#8 private keys, and
SubjectPublicKeyInfo public keys with their corresponding PEM delimiters.

For encrypted PKCS#8 PEM, supply the password to the import method:

```csharp
using RSA key = RSA.Create();
key.ImportFromEncryptedPem(File.ReadAllText("encrypted-private-key.pem"), password);
```

For a DER-encoded PKCS#8 private key:

```csharp
using RSA key = RSA.Create();
byte[] encoded = File.ReadAllBytes("private-key.der");
key.ImportPkcs8PrivateKey(encoded, out int bytesRead);
```

`bytesRead` reports how many bytes the import consumed. Choose
`ImportRSAPrivateKey` for PKCS#1 private keys, `ImportRSAPublicKey` for PKCS#1
public keys, `ImportSubjectPublicKeyInfo` for SubjectPublicKeyInfo public keys,
or `ImportEncryptedPkcs8PrivateKey` for encrypted PKCS#8. These DER import methods
also report `bytesRead`.

If the caller already has an `RSAParameters` value:

```csharp
using RSA key = RSA.Create();
key.ImportParameters(parameters);
```

Imports use platform validation, including its supported legacy key sizes.
They do not apply the Gearbox generation size policy below.

## Generating new keys

Prefer native `RSA.Create(bitLength)` for ordinary generation:

```csharp
using RSA generated = RSA.Create(2048);
```

Use `RSAKeyGenerator` when cooperative cancellation or deliberate algorithm
control is needed. Custom generation has no claimed security or performance
advantage over platform generation:

```csharp
using System.Security.Cryptography;
using Gearbox.Cryptography;

using RSA generated =
    await RSAKeyGenerator.GenerateAsync(2048, cancellationToken);
byte[] signature = generated.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
bool valid = generated.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
```

`RSAKeyGenerator.Generate(int bitLength, CancellationToken cancellationToken = default)`
returns an initialized `RSA`, and `RSAKeyGenerator.GenerateAsync` with the same
arguments returns `Task<RSA>`. The caller must dispose the returned provider.

- `bitLength` describes the **exact modulus bit length**, from 2,048 through
  16,384 inclusive. It must also match the current provider's `LegalKeySizes`.
  The Windows provider uses 64-bit increments; other platforms may differ.
  Unsupported values throw `ArgumentOutOfRangeException` without rounding or
  clamping. Validation is synchronous on both factories.
- The public exponent is fixed at **65537**, encoded as `01 00 01`.
- P and Q each have half the requested bit length. Each must be compatible with
  the exponent: `gcd(65537, prime - 1) == 1`.
- P and Q must be distinct, with `|p - q| > 2^(bitLength / 2 - 100)`.
- A rejected P is replaced. An incompatible, duplicate, or insufficiently
  separated Q is replaced while retaining P. If their product has one bit less
  than requested, both primes are replaced and the pair search restarts.

Each `Prime` search draws fresh random candidates and uses the existing
Miller–Rabin/Lucas checks described in [prime-generation.md](prime-generation.md).
The RSA factories do not repeat primality testing or alter its randomness policy.
P and Q searches run sequentially because each large prime search already uses
up to all physical cores. Concurrent factory calls have separate operation state
and can each create their own prime worker pool.

## Static parameter and PEM helpers

`RSAKey.CreateFullKeyParameters(exponent, p, q)` computes `n = p*q`,
`d = e^-1 mod ((p-1)*(q-1))`, and the CRT values. Its four-argument overload
also verifies the supplied modulus. Both return all eight unsigned big-endian
arrays: D has the modulus width, and P, Q, DP, DQ, and InverseQ have half that
width, rounded up, with leading-zero padding. Primality is the caller's
responsibility.

`RSAKey.EncodeParametersPem(parameters)` encodes a complete two-prime private
key in an unencrypted PKCS #1 `RSA PRIVATE KEY` envelope, with Base64 wrapped
at 76 characters and no newline after the closing delimiter. All eight arrays
must be non-null and non-empty. Leading-zero padding is accepted and removed
from the DER integers; the helper does not check mathematical consistency.
It leaves input arrays untouched and clears the writer's temporary DER data.
The certificate extension continues to use this helper for private-key export.

## RSA behavior and ownership

The custom generator creates one platform provider, uses its `LegalKeySizes`
for validation, imports the generated parameters, and returns that exact
instance. Standard .NET RSA operations and import/export methods use the
provider directly. Public-only imports support encryption and verification;
private operations require private parameters and follow provider errors.

`KeySize` and `LegalKeySizes` expose provider behavior. Assigning `KeySize`
uses platform key generation, and importing parameters uses platform validation.
These operations can accept legacy sizes that the Gearbox generation factories
reject.

Imports do not retain or clear caller-owned arrays. Exported arrays are separate
from provider storage and belong to the caller. Factory-created parameter arrays
are cleared with `CryptographicOperations.ZeroMemory` after import, on both
success and failure. The factory owns the provider until successful return and
disposes it on validation failure, cancellation, prime-search failure, derivation
failure, or import failure. After return, disposal belongs to the caller.

This separation removes the instance wrapper and moves custom generation to
`RSAKeyGenerator`. Callers use `RSA` and `Task<RSA>` directly; the static helper
signatures and output contracts remain unchanged. This is a source-breaking
change without compatibility aliases.

Immutable `BigInteger` values cannot be reliably erased. Private-key strings
also cannot be reliably cleared; callers own and manage exported key material.

## Cancellation and asynchronous execution

A valid pre-canceled synchronous request throws `OperationCanceledException`.
A valid pre-canceled asynchronous request returns a canceled task. Both preserve
the caller's token and perform no prime search. Size validation precedes this
cancellation check, so an invalid size still raises an argument error.

Cancellation is checked before and after each prime search and around parameter
derivation and native import. Those synchronous derivation/import calls, and
individual `BigInteger` operations inside prime generation, cannot be interrupted
internally. Cancellation after import disposes the unpublished key and clears
the generated parameter arrays.

The asynchronous factory awaits `Prime.GenerateAsync` sequentially with
`ConfigureAwait(false)` rather than blocking a thread-pool thread around the
synchronous factory. It awaits an active prime search's completion, including
worker cleanup, before reporting cancellation or failure.

## Validation

`RSAKeyTests` shares the existing fixtures across its two partial-class files.
Tests cover size profiles, deterministic pair rejection, exact modulus width,
cancellation, asynchronous sequencing and failure propagation, parameter
clearing, provider identity and ownership, and real 2,048-bit generation through
both factories with mathematical checks, signing, encryption, and PEM round-trips.
The parameter-helper tests and exact PEM fixtures also cover the certificate
extension's existing export behavior.

```powershell
dotnet test tests/Gearbox.Tests/Gearbox.Tests.csproj --filter 'FullyQualifiedName~RSAKeyTests'
dotnet test tests/Gearbox.Tests/Gearbox.Tests.csproj
```
