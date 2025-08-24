# pskc-creator
🔐 PSKC Creator

PSKC Creator is a simple Java tool that converts token information stored in a `.csv` file into a Portable Symmetric Key Container (PSKC) file following the RFC 6030 standard.  
The generated `.xml` output can be directly imported into identity and authentication systems that support PSKC (e.g., OTP/TOTP tokens).

---

## Features

- Import tokens in **Base32** or **Hexadecimal** format.
- Export tokens as:
    - CSV in hexadecimal format
    - PSKC XML
    - Encrypted PSKC XML using AES-128-CBC + HMAC-SHA1
- Generates a random pre-shared key for encryption and saves it for distribution.

---

## CSV Template

The input CSV must have the following columns:

```
Serial          , Secret           , Type, Length, TimeStep, Issuer
1234567890123456, JBSWY3DPEHPK3PXP , TOTP, 6     , 30      , IssuerName
2345678901234567, NB2W45DFOIZA     , TOTP, 6     , 30      , IssuerName2
```

- **Serial**: Token serial number
- **Secret**: Secret key in **Base32** format
- **Type**: `TOTP` or `HOTP`
- **Length**: Number of digits for the OTP
- **TimeStep**: OTP interval in seconds (for TOTP)
- **Issuer**: Optional, defaults to `Unknown`

---

## Usage

### Convert CSV to PSKC without encryption

```bash
java -jar build/libs/pskc-creator-1.0-SNAPSHOT-all.jar tokens.csv
```
Generates: tokens.pskc

Secrets are stored in Base64 plaintext.

### Convert CSV to PSKC with encryption
```bash
java -jar build/libs/pskc-creator-1.0-SNAPSHOT-all.jar tokens.csv --encrypt
```

Generates: tokens_encrypted.pskc

`A random 32-byte pre-shared key is generated and saved to preshared_key.txt.`

Secrets are encrypted using AES-128-CBC and protected with HMAC-SHA1.