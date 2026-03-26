const FERNET_VERSION = 0x80;

/**
 * Provides Fernet symmetric encryption and decryption utilities.
 *
 * This class allows encrypting and decrypting strings, ArrayBufferLike, and JSON objects
 * using the Fernet symmetric encryption scheme. It also provides utilities for
 * token age calculation and expiration checks.
 *
 * @remarks
 * - The secret key can be provided or generated automatically using generateSecret().
 * - The default TTL (time-to-live) can be set for token expiration checks.
 *
 * @example
 * ```TypeScript
 * const secret = Fernet.generateSecret();
 * const fernet = new Fernet(secret, 3600);
 * const token = await fernet.encrypt('my data');
 * const decrypted = await fernet.decrypt(token);
 * ```
 */
export class Fernet {
  private readonly secret: string;
  private readonly signingKey: Promise<CryptoKey>;
  private readonly encryptionKey: Promise<CryptoKey>;
  private readonly defaultTTL: number;

  constructor(secret?: string, defaultTTL: number = 0) {
    this.secret = secret ?? Fernet.generateSecret();

    const { signingKey, encryptionKey } = Fernet.deriveKeys(this.secret);
    this.encryptionKey = crypto.subtle.importKey(
      "raw",
      encryptionKey,
      { name: "AES-CBC" },
      false,
      ["encrypt", "decrypt"],
    );
    this.signingKey = crypto.subtle.importKey(
      "raw",
      signingKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );

    this.defaultTTL = defaultTTL;
  }

  /**
   * Derives signing and encryption keys from a 32-byte url-safe base64-encoded secret.
   *
   * @param secret - A 32-byte url-safe base64-encoded string used as the source for key derivation.
   * @returns An object containing a 128-bit signing key and a 128-bit encryption key as Uint8Arrays.
   * @throws {Error} If the provided secret is not a valid 32-byte url-safe base64-encoded string.
   */
  static deriveKeys(secret: string): {
    signingKey: Uint8Array<ArrayBuffer>;
    encryptionKey: Uint8Array<ArrayBuffer>;
  } {
    let secretBuffer: Uint8Array<ArrayBuffer>;
    try {
      secretBuffer = base64UrlToUint8Array(secret);

      if (secretBuffer.length !== 32) {
        throw new Error();
      }
    } catch {
      throw new Error("Secret must be 32 url-safe base64-encoded bytes");
    }

    // 128-bits signing key
    const signingKey = secretBuffer.subarray(0, 16);
    // 128-bits encryption key
    const encryptionKey = secretBuffer.subarray(16, 32);

    return { signingKey, encryptionKey };
  }

  /**
   * Generates a new random secret key encoded in base64url format with proper padding.
   *
   * @returns A base64url-encoded string representing a 32-byte random secret, padded to a valid length.
   */
  static generateSecret(padding: boolean = true): string {
    const secretBuffer = new Uint8Array(32);
    crypto.getRandomValues(secretBuffer);
    let secret = uint8ArrayToBase64Url(secretBuffer);

    if (padding) {
      secret += "=".repeat((4 - (secret.length % 4)) % 4);
    }

    return secret;
  }

  /**
   * Retrieves the secret key used for cryptographic operations.
   *
   * @returns The secret key as a string.
   */
  getSecret(): string {
    return this.secret;
  }

  /**
   * Encrypts data using the Fernet symmetric encryption scheme.
   *
   * @param data - The plaintext data to encrypt, as a string or ArrayBufferLike.
   * @param padding - Optional. Whether to add base64 padding to the token. Defaults to true.
   * @returns The Fernet token as a base64url-encoded string.
   */
  async encrypt(
    data: string | ArrayBufferLike | ArrayBufferView,
    padding: boolean = true,
  ): Promise<string> {
    const plaintextData = toStandardUint8Array(data);

    // random IV
    const iv = new Uint8Array(16);
    crypto.getRandomValues(iv);

    // current timestamp, 8-bytes, big-endian
    const timestamp = new Uint8Array(8);
    const view = new DataView(timestamp.buffer);
    view.setBigUint64(0, BigInt(Math.floor(Date.now() / 1000)), false); // false -> big endian

    // encrypt the data with AES-128-CBC
    const cryptoKey = await this.encryptionKey;
    const encryptedText = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-CBC", iv: iv },
        cryptoKey,
        plaintextData,
      ),
    );

    // token = version(1) + timestamp(8) + iv(16) + encrypted_text + hmac(32)
    const tokenWithoutHmac = new Uint8Array(
      1 + timestamp.length + iv.length + encryptedText.length,
    );
    tokenWithoutHmac[0] = FERNET_VERSION;
    tokenWithoutHmac.set(timestamp, 1);
    tokenWithoutHmac.set(iv, 9);
    tokenWithoutHmac.set(encryptedText, 25);

    // calculate HMAC
    const hmacKey = await this.signingKey;
    const signature = new Uint8Array(
      await crypto.subtle.sign("HMAC", hmacKey, tokenWithoutHmac),
    );

    // final token
    const token = new Uint8Array(tokenWithoutHmac.length + signature.length);
    token.set(tokenWithoutHmac, 0);
    token.set(signature, tokenWithoutHmac.length);

    //! Important!
    // Python cryptography.fernet requires a base64url format input that must be aligned with '='.
    // But base64url will remove the trailing '='.
    // WTF??
    let tokenEncoded = uint8ArrayToBase64Url(token);
    if (padding) {
      const padding = "=".repeat((4 - (tokenEncoded.length % 4)) % 4);
      tokenEncoded += padding;
    }

    return tokenEncoded;
  }

  /**
   * Decrypts a Fernet-encrypted token using the provided secret.
   *
   * This function verifies the token's HMAC, checks its version, validates the TTL (if provided),
   * and decrypts the cipher text using AES-128-CBC.
   *
   * @param token - The Fernet-encrypted token, encoded in base64url format.
   * @param ttl - Optional. Time-to-live in seconds. If greater than 0, the token's age is checked against this value.
   * @returns The decrypted payload as a Uint8Array.
   * @throws {Error} If the token is too short, has an invalid version, fails HMAC verification, or is expired.
   */
  async decrypt(token: string, ttl?: number): Promise<Uint8Array<ArrayBuffer>> {
    const tokenData = base64UrlToUint8Array(token);

    // version(1) + timestamp(8) + iv(16) + minimal cipher(16) + HMAC(32)
    if (tokenData.length < 73) {
      throw new Error("Token too short");
    }

    const version = tokenData[0];
    if (version !== FERNET_VERSION) {
      throw new Error("Invalid token version");
    }

    const timestamp = tokenData.subarray(1, 9);
    const iv = tokenData.subarray(9, 25);
    const cipherText = tokenData.subarray(25, -32);
    const providedHmac = tokenData.subarray(-32);

    // verity HMAC
    const tokenWithoutHmac = tokenData.subarray(0, -32);
    const hmacKey = await this.signingKey;
    const isValid = await crypto.subtle.verify(
      "HMAC",
      hmacKey,
      providedHmac,
      tokenWithoutHmac,
    );

    if (!isValid) {
      throw new Error("HMAC verification failed");
    }

    // TTL check
    ttl = ttl ?? this.defaultTTL;
    if (ttl > 0) {
      const dataView = new DataView(
        timestamp.buffer,
        timestamp.byteOffset,
        timestamp.byteLength,
      );
      const tokenTimestamp = dataView.getBigUint64(0, false);
      const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
      const age = Number(currentTimestamp - tokenTimestamp);

      if (tokenTimestamp > currentTimestamp) {
        throw new Error("Token timestamp is in the future");
      }
      if (age > ttl) {
        throw new Error("Token has expired");
      }
    }

    // decrypt
    const cryptoKey = await this.encryptionKey;
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-CBC", iv },
        cryptoKey,
        cipherText,
      ),
    );
  }

  // TODO: encrypt_at_time & decrypt_at_time

  /**
   * Decrypts a Fernet-encrypted token and returns the result as a UTF-8 string.
   *
   * @param token - The Fernet-encrypted token.
   * @param utfLabel - Optional. The text encoding. Default: "utf-8".
   * @param ttl - Optional. TIme-to-live seconds.
   * @returns The decrypted payload as a string
   */
  async decryptText(
    token: string,
    utfLabel: string = "utf-8",
    ttl?: number,
  ): Promise<string> {
    const decrypted = await this.decrypt(token, ttl);
    return new TextDecoder(utfLabel).decode(decrypted);
  }

  /**
   * Encrypts a JavaScript object or value as a JSON string using Fernet symmetric encryption.
   *
   * @param data - The data to be encrypted. This can be any value that is serializable to JSON.
   * @param padding - Optional. Whether to add base64 padding to the token. Defaults to true.
   * @returns The encrypted string produced by Fernet.
   * @throws {Error} If the data cannot be stringified to JSON.
   */
  async encryptJSON(data: any, padding: boolean = true): Promise<string> {
    try {
      const jsonString = JSON.stringify(data);
      return await this.encrypt(jsonString, padding);
    } catch {
      throw new Error("Input data cannot be stringified");
    }
  }

  /**
   * Decrypts a Fernet-encrypted token and parses the resulting JSON string into an object of type `T`.
   *
   * @template T - The expected type of the parsed JSON object.
   * @param token - The Fernet-encrypted token to decrypt.
   * @param ttl - Optional. The time-to-live (in seconds) for the token. Defaults to 0 (no TTL check).
   * @returns The decrypted and parsed object of type `T`.
   * @throws {Error} If decryption fails or the JSON is invalid.
   */
  async decryptJSON<T = any>(token: string, ttl?: number): Promise<T> {
    const decrypted = await this.decrypt(token, ttl);
    const jsonString = new TextDecoder().decode(decrypted);
    return JSON.parse(jsonString) as T;
  }

  // TODO: extract_timestamp

  /**
   * Calculates and returns the age of the provided token in seconds.
   *
   * @param token - The token string whose age is to be determined.
   * @returns The age of the token in seconds.
   * @throws {Error} If the token is too short to contain a valid timestamp.
   */
  static getTokenAge(token: string): number {
    const decryptedToken = base64UrlToUint8Array(token);
    if (decryptedToken.length < 73) {
      throw new Error("Token too short");
    }

    const timestamp = decryptedToken.subarray(1, 9);
    const dataView = new DataView(
      timestamp.buffer,
      timestamp.byteOffset,
      timestamp.byteLength,
    );
    const tokenTimestamp = dataView.getBigUint64(0, false);
    const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));

    return Number(currentTimestamp - tokenTimestamp);
  }

  /**
   * Determines whether a given token has expired based on its time-to-live (TTL).
   *
   * @param token - The token string to check for expiration.
   * @param ttl - Optional. The time-to-live in seconds. If not provided, the default TTL is used.
   * @returns `true` if the token is expired; otherwise, `false`.
   */
  isTokenExpired(token: string, ttl?: number): boolean {
    const age = Fernet.getTokenAge(token);
    return age > (ttl ?? this.defaultTTL);
  }
}

/* === help function === */

// "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP_CODES = new Uint8Array([
  65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
  84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106,
  107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
  122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95,
]);

const REVERSE_LOOKUP_CODE = new Uint8Array(256).fill(255); // 255 -> invalid char
for (let i = 0; i < LOOKUP_CODES.length; i++) {
  REVERSE_LOOKUP_CODE[LOOKUP_CODES[i]] = i;
}

/**
 * Converts a base64url-encoded string to a Uint8Array.
 *
 * @param str - The base64url-encoded string to convert.
 * @returns A Uint8Array containing the decoded bytes.
 */
function base64UrlToUint8Array(str: string): Uint8Array<ArrayBuffer> {
  if (typeof Buffer !== "undefined") {
    // NodeJS
    return new Uint8Array(Buffer.from(str, "base64url"));
  }

  // browser
  let len = str.length;
  // handle optional padding
  while (len > 0 && str[len - 1] === "=") {
    len--;
  }

  // Standard base64url string length (mod 4) can only be 0, 2, or 3.
  if (len % 4 === 1) {
    throw new Error("Invalid base64url string length");
  }

  const output = new Uint8Array(Math.floor((len * 3) / 4));
  let i = 0;
  let j = 0;
  while (i < len) {
    const code1 = str.charCodeAt(i++);
    const code2 = i < len ? str.charCodeAt(i++) : 65; // 'A' as default for valid padding
    const code3 = i < len ? str.charCodeAt(i++) : 61; // '='
    const code4 = i < len ? str.charCodeAt(i++) : 61; // '='

    const v1 = REVERSE_LOOKUP_CODE[code1];
    const v2 = REVERSE_LOOKUP_CODE[code2];
    const v3 = code3 === 61 ? 64 : REVERSE_LOOKUP_CODE[code3];
    const v4 = code4 === 61 ? 64 : REVERSE_LOOKUP_CODE[code4];

    if (v1 === 255 || v2 === 255 || v3 === 255 || v4 === 255) {
      throw new Error("Invalid character in base64url string");
    }

    output[j++] = (v1 << 2) | (v2 >> 4);
    if (v3 < 64) {
      output[j++] = ((v2 & 15) << 4) | (v3 >> 2);
      if (v4 < 64) {
        output[j++] = ((v3 & 3) << 6) | v4;
      }
    }
  }

  return output;
}

/**
 * Converts a Uint8Array to a base64url-encoded string.
 *
 * @param array - The Uint8Array to encode.
 * @returns A base64url-encoded string (without padding).
 */
function uint8ArrayToBase64Url(array: Uint8Array<ArrayBuffer>): string {
  if (typeof Buffer !== "undefined") {
    // NodeJS
    return Buffer.from(array).toString("base64url");
  }

  // browser
  const len = array.length;
  // Maximum possible length is ceil(len / 3) * 4
  const output = new Uint8Array(Math.ceil(len / 3) * 4);

  // Table lookup method convert u8 -> char
  // In 24MiB large data test, reference benchmark: string += method (32KiB chunked) & atob API
  // Firefox:   ~2000ms -> ~500ms
  // Chromium:  ~2300ms -> ~1400ms
  let j = 0;
  for (let i = 0; i < len; i += 3) {
    const b1 = array[i];
    const b2 = i + 1 < len ? array[i + 1] : 0;
    const b3 = i + 2 < len ? array[i + 2] : 0;

    output[j++] = LOOKUP_CODES[b1 >> 2];
    output[j++] = LOOKUP_CODES[((b1 & 3) << 4) | (b2 >> 4)];
    if (i + 1 < len) {
      output[j++] = LOOKUP_CODES[((b2 & 15) << 2) | (b3 >> 6)];
    }
    if (i + 2 < len) {
      output[j++] = LOOKUP_CODES[b3 & 63];
    }
  }

  return new TextDecoder().decode(output.subarray(0, j));
}

/**
 * Converts input data to a standard Uint8Array. (no shared)
 *
 * @param data - The data to convert, can be a string or ArrayBufferLike.
 * @returns A Uint8Array containing the data.
 */
function toStandardUint8Array(
  data: string | ArrayBufferLike | ArrayBufferView,
): Uint8Array<ArrayBuffer> {
  if (typeof data === "string") {
    return new TextEncoder().encode(data);
  }

  // Create a copy of the buffer data
  const byteLength = data.byteLength;
  const newBuffer = new ArrayBuffer(byteLength);
  const targetView = new Uint8Array(newBuffer);

  if (data instanceof ArrayBuffer) {
    targetView.set(new Uint8Array(data));
  } else if (data instanceof SharedArrayBuffer) {
    targetView.set(new Uint8Array(data));
  } else {
    // ArrayBufferView (Uint8Array, etc.)
    targetView.set(
      new Uint8Array(data.buffer, data.byteOffset, data.byteLength),
    );
  }

  return targetView;
}
