# vault

A small, dependency-light Python implementation of the **TTEncrypt** payload format: gzip compression, a SHA-512 checksum, and AES-128-CBC, wrapped in a salted envelope.

```python
from vault import enc, dec

blob = enc("hello world")
print(dec(blob))  # hello world
```

## Features

- Compatible with the TTEncrypt wire format (encrypt and decrypt)
- Single file, one dependency (`pycryptodome`)
- Accepts `str` or bytes-like input, returns `str` or raw `bytes` on decrypt
- Optional fixed nonce for reproducible output
- Clear errors via `SealError` (a `ValueError` subclass)

## Install

```bash
pip install pycryptodome
```

Then drop `vault.py` into your project.

## Usage

### Functions

```python
from vault import enc, dec

blob = enc("some text")            # bytes
text = dec(blob)                   # "some text"
raw  = dec(blob, encoding=None)    # b"some text"
```

### Fixed nonce

Pass a 32-byte nonce to get deterministic output:

```python
nonce = bytes(32)
assert enc("data", nonce) == enc("data", nonce)
```

### Class wrapper

```python
from vault import Vault

v = Vault(nonce=bytes(32))   # nonce is optional
blob = v.encrypt("data")
v.decrypt(blob)
```

### Errors

```python
from vault import dec, SealError

try:
    dec(b"not a payload")
except SealError as e:
    print(e)
```

## API

| Name | Description |
| --- | --- |
| `enc(payload, nonce=None)` | Encrypt `str` or bytes-like data. `nonce` must be 32 bytes; random if omitted. Returns `bytes`. |
| `dec(blob, encoding="utf-8")` | Decrypt a payload. Returns `str`, or `bytes` if `encoding=None`. |
| `Vault(nonce=None)` | Wrapper with `.encrypt()` and `.decrypt()` methods that call `enc` and `dec`. |
| `SealError` | Raised for malformed payloads, bad padding, or a wrong nonce size. |

## Format

```
┌───────────┬───────────┬──────────────────────────────────────┐
│ TAG (6 B) │ NONCE (32)│ AES-128-CBC( sha512(body) ‖ body )   │
└───────────┴───────────┴──────────────────────────────────────┘
```

- **TAG:** `74 63 05 10 00 00`
- **body:** gzip (level 9) of the input, with the 10-byte gzip header normalized to `1f 8b 08` followed by seven zero bytes
- **checksum:** SHA-512 of `body`, prepended to it (64 bytes)
- **padding:** PKCS#7, 16-byte blocks
- **key / IV:** `d = sha512(sha512(nonce) ‖ seasoning)`; key is `d[0:16]`, IV is `d[16:32]`

## Known quirks

Payloads produced by the original implementation can occasionally be corrupt: it lets a salt byte reach 256, hashes it as 256, then writes 0. This affects roughly 1 in 9 payloads and shows up as a bad-padding `SealError` on decrypt. This library does not have that bug when encrypting.

