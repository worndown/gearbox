# RSA keys

Use `System.Security.Cryptography.RSA` for key import, export, signing, and
encryption. `Gearbox.Cryptography.RSAKey` adds custom key generation through
Gearbox's `Prime` implementation and parameter derivation from known primes.

## Generating keys

Prefer platform generation for ordinary use:

```csharp
using System.Security.Cryptography;

using RSA key = RSA.Create(2048);
```

Use `RSAKey` when you need cooperative cancellation or generation through
Gearbox's prime searches. It offers no claimed security or performance advantage
over platform generation:

```csharp
using System.Security.Cryptography;
using Gearbox.Cryptography;

using RSA key = await RSAKey.GenerateAsync(2048, cancellationToken);
byte[] signature = key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
bool valid = key.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
```

`RSAKey.Generate(bitLength, cancellationToken)` returns `RSA` synchronously;
`RSAKey.GenerateAsync` takes the same arguments and returns `Task<RSA>`.
The cancellation token is optional. Dispose the returned key when finished.

- The modulus has exactly the requested bit length: 2,048 through 16,384 bits,
  subject to the platform provider's `LegalKeySizes`. Windows uses 64-bit
  increments; other platforms may differ. Unsupported sizes throw
  `ArgumentOutOfRangeException` without rounding. Both methods validate
  arguments synchronously.
- The public exponent is 65537. P and Q each have half the modulus bit length,
  are distinct, satisfy `gcd(65537, prime - 1) == 1`, and have
  `|p - q| > 2^(bitLength / 2 - 100)`. Both primes are replaced if their product
  is too short.
- Prime searches run sequentially; each search may use all physical cores.
  See [prime-generation.md](prime-generation.md) for the primality checks.

Cancellation is checked between searches and around parameter derivation and
native import. Individual `BigInteger` operations and derivation/import cannot
be interrupted. The async method awaits each prime search, including worker
cleanup, without capturing the synchronization context.

For a valid request, a pre-canceled token causes the synchronous method to throw
`OperationCanceledException` and the async method to return a canceled task;
both preserve the caller's token and perform no prime search. Invalid sizes
still raise an argument error first.

Generation clears its temporary parameter arrays after import and disposes the
provider on failure or cancellation. The caller owns the provider after a
successful return. Immutable `BigInteger` values cannot be reliably erased.
Later imports and `KeySize` assignments follow platform behavior, including
platform generation and size rules.

## Loading and exporting keys

```csharp
using RSA key = RSA.Create();
key.ImportFromPem(File.ReadAllText("private-key.pem"));
string pem = key.ExportRSAPrivateKeyPem();
```

`ImportFromPem` accepts PKCS#1 RSA private/public keys, PKCS#8 private keys, and
SubjectPublicKeyInfo public keys. For encrypted PKCS#8 PEM, use
`ImportFromEncryptedPem(pem, password)`. For an existing `RSAParameters` value,
use `ImportParameters(parameters)`. These imports use platform validation and
do not apply the custom generation size limits.

Choose the export format required by the consumer:

| Method | PEM format |
| --- | --- |
| `ExportRSAPrivateKeyPem()` | Unencrypted PKCS#1, `RSA PRIVATE KEY` |
| `ExportPkcs8PrivateKeyPem()` | Unencrypted PKCS#8, `PRIVATE KEY` |
| `ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters)` | Encrypted PKCS#8, `ENCRYPTED PRIVATE KEY` |
| `ExportSubjectPublicKeyInfoPem()` | SubjectPublicKeyInfo, `PUBLIC KEY` |

For DER, use the corresponding methods without the `Pem` suffix. DER import
methods also return `bytesRead`, the number of bytes consumed.

The certificate extension `ExportPrivateKeyPem()` delegates to
`RSA.ExportRSAPrivateKeyPem()`. It requires an exportable RSA private key and
returns unencrypted PKCS#1 PEM. The .NET exporter wraps Base64 at 64 characters
with LF line endings and no newline after the closing delimiter.

Exported arrays and strings belong to the caller. Clear private parameter arrays
when finished; private-key strings cannot be reliably cleared.

## Deriving parameters from known primes

`RSAKey.CreateFullKeyParameters(exponent, p, q)` computes the modulus, private
exponent, and CRT values. The four-argument overload also checks that the supplied
modulus equals `p * q`. Primality is the caller's responsibility. The exponent
must be odd, greater than one, less than the modulus, and coprime to
`(p - 1) * (q - 1)`; P and Q must be distinct odd primes greater than two.

Both overloads return all eight unsigned big-endian `RSAParameters` arrays.
D has the modulus byte width; P, Q, DP, DQ, and InverseQ have half that width,
rounded up and padded with leading zeros. Each prime must fit that width.
Import the result with `RSA.ImportParameters`; the caller owns and clears the
returned arrays.

## Refactoring migration

Replace `RSAKeyGenerator.Generate` / `GenerateAsync` with `RSAKey.Generate` /
`GenerateAsync`. The parameter-derivation overloads are unchanged.

Replace `RSAKey.EncodeParametersPem(parameters)` by importing the parameters
into an `RSA` instance and calling `ExportRSAPrivateKeyPem()`. This applies
platform key validation. PEM output now uses the platform's 64-character lines
and LF line endings, replacing the helper's 76-character lines and Windows CRLF.
The encoded key format remains PKCS#1. These API changes have no compatibility
aliases.

To run the relevant checks:

```powershell
dotnet test tests/Gearbox.Tests/Gearbox.Tests.csproj -c Release --filter 'FullyQualifiedName~RSAKeyTests|FullyQualifiedName~CertificateTests'
```
