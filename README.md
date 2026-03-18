# Fernet-TS

Python [Cryptography.Fernet](https://cryptography.io/en/latest/fernet/) symmetric encryption, implemented in TypeScript.

Fully compatible with Python's `cryptography.fernet` module
using AES-128-CBC for encryption and HMAC-SHA256 for authentication.
Works in both Node.js and browsers, powered by the Web Crypto API.

## Install

```bash
npm install @gsgfs/fernet
```

## Usage

### Quick Start

Decrypt an existing token:

```TypeScript
import { Fernet } from "@gsgfs/fernet"

const secret = "DdivR60zj0gvL-6PG1nAj8SwSvyHW0SVxNI3JSvdGLE=";
const token = "gAAAAABpuuo1hxb4p-UnO_KH3OajIgM25-MvtGErt51GHJ-id4r91S-0ChFxxoehwu6SnUzAk4_ulUPHJiIIMkQXen5Rbr3cPIQ4s89WKNCAr6PwYuI2vP0=";

const f = new Fernet(secret);
const decrypted = await f.decrypt(token);        // return Uint8Array
const text = await f.decryptText(token);         // return string
console.log(text);
```

Encrypt new data:

```TypeScript
import { Fernet } from "@gsgfs/fernet"

const f = new Fernet();  // auto-generates secret
const secret = f.getSecret();  // save this for later decryption

const token = await f.encrypt("Hello from Fernet-TS!");
console.log(token);
```

### Working with JSON

Python and TypeScript have different serialization behaviors,
which may require attention when exchanging data between them.

```TypeScript
// Encrypt any JSON-serializable data
const data = { "Nishiki Asumi": "Yukige Shiki" };
const token = await f.encryptJSON(data);

// Decrypt back to typed object
const restored = await f.decryptJSON<typeof data>(token);
```

### TTL and Token Validation

```TypeScript
// Set default TTL (in seconds) in constructor
const f = new Fernet(secret, 3600);  // 1 hour default TTL

// Or specify TTL per-decrypt operation
await f.decrypt(token, 60);  // 60 seconds TTL

// Check token age without decrypting
const age = Fernet.getTokenAge(token);  // seconds
const expired = f.isTokenExpired(token, 3600);
```

### Python Interoperability

Tokens created by this library can be decrypted by Python's `cryptography.fernet`, and vice versa:

```Python
from cryptography.fernet import Fernet

key = Fernet.generate_key()
fernet = Fernet(key)

# Python encrypts
token = fernet.encrypt(b"Hello from Python!")
```

```TypeScript
// TypeScript decrypts (use the same key)
const f = new Fernet(key);
const msg = await f.decryptText(token);
```

Note: Python's `cryptography.fernet` requires base64 tokens to include `=` padding.
Since TypeScript's `base64url` encoding removes trailing `=` by default,
this library automatically adds padding to ensure compatibility.

Use `f.encrypt(data, false)` to disable automatic padding.
