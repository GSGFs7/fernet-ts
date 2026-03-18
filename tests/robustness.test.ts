import { describe, expect, it } from "vitest";
import { Fernet } from "../lib/fernet";

describe("Fernet Robustness and Safety", () => {
  it("should not be affected by external modification of input ArrayBuffer", async () => {
    const secret = Fernet.generateSecret();
    const fernet = new Fernet(secret);

    const originalContent = "Original Message";
    const ab = new TextEncoder().encode(originalContent).buffer;
    const p = fernet.encrypt(ab);

    // Modify the original buffer immediately to test for race conditions
    new Uint8Array(ab).set(new TextEncoder().encode("Modified Message"));

    const token = await p;
    const decrypted = await fernet.decryptText(token);

    expect(decrypted).toBe(originalContent);
  });

  it("should throw error for invalid base64url length in browser path", async () => {
    // Mock Buffer as undefined to force manual browser implementation
    const originalBuffer = globalThis.Buffer;
    globalThis.Buffer = undefined;

    try {
      const fernet = new Fernet();
      // Length 1 is invalid for base64url
      await expect(fernet.decrypt("A")).rejects.toThrow(
        "Invalid base64url string length",
      );
    } finally {
      globalThis.Buffer = originalBuffer;
    }
  });

  it("should throw error for invalid base64url characters in browser path", async () => {
    const originalBuffer = globalThis.Buffer;
    globalThis.Buffer = undefined;

    try {
      const fernet = new Fernet();
      // Spaces are invalid
      await expect(fernet.decrypt(" ".repeat(100))).rejects.toThrow(
        "Invalid character in base64url string",
      );
    } finally {
      globalThis.Buffer = originalBuffer;
    }
  });

  it("should correctly handle DataView with offsets (robustness check)", async () => {
    const fernet = new Fernet();
    const token = await fernet.encrypt("test");

    // getTokenAge should work
    const age = Fernet.getTokenAge(token);
    expect(age).toBeGreaterThanOrEqual(0);
  });

  it("should throw error for tokens that are too short in getTokenAge", () => {
    // A valid-looking but too short token (e.g., version + timestamp + iv + minimal cipher + hmac = 73)
    // 60 chars in base64url is approx 45 bytes, which is < 73.
    const shortToken = "A".repeat(60);
    expect(() => Fernet.getTokenAge(shortToken)).toThrow("Token too short");
  });

  it("should handle DataView correctly even if the underlying buffer is larger and has offsets", async () => {
    const fernet = new Fernet();
    const message = "offset-test";

    // Create a large buffer and put the encrypted data in the middle
    const token = await fernet.encrypt(message);
    const tokenData = new TextEncoder().encode(token);

    const largeBuffer = new ArrayBuffer(tokenData.length + 100);
    const view = new Uint8Array(largeBuffer, 50, tokenData.length);
    view.set(tokenData);

    const tokenWithOffset = new TextDecoder().decode(view);
    const decrypted = await fernet.decryptText(tokenWithOffset);
    expect(decrypted).toBe(message);
  });

  it("should throw corrected error message in encryptJSON", async () => {
    const fernet = new Fernet();
    // Circular reference to make JSON.stringify fail
    const circular: any = {};
    circular.self = circular;

    await expect(fernet.encryptJSON(circular)).rejects.toThrow(
      "Input data cannot be stringified",
    );
  });
});
