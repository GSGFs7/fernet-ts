import { describe, expect, it } from "vitest";
import { Fernet } from "../lib/fernet";

async function runMainTest() {
  const isNode = typeof Buffer !== "undefined";
  console.log(`Running in ${isNode ? "NodeJS" : "Browser"}`);

  const fernet = new Fernet();

  const originalText = "114_-^514";
  const token = await fernet.encrypt(originalText);

  const decrypted = await fernet.decrypt(token);
  const resultText = new TextDecoder().decode(decrypted);

  expect(resultText).toBe(originalText);
  expect(token).toMatch(/^[A-Za-z0-9\-_=]+$/); // base64url
}

async function runLargeDataTest() {
  const fernet = new Fernet();
  const dataSize = 24 * 1024 * 1024; // 24MiB
  const largeData = new Uint8Array(dataSize).fill(0x42);

  const token = await fernet.encrypt(largeData.buffer);
  const decrypted = await fernet.decrypt(token);

  const decryptedArray = new Uint8Array(decrypted);
  expect(decryptedArray.length).toBe(largeData.length);

  // faster comparison for large data
  let isEqual = true;
  for (let i = 0; i < decryptedArray.length; i++) {
    if (decryptedArray[i] !== largeData[i]) {
      isEqual = false;
      break;
    }
  }
  expect(isEqual).toBe(true);
}

describe("Real Browser Test", () => {
  it("should work with Web Crypto in real browser", async () => {
    await runMainTest();
  });

  it("should handle large data without stack overflow (btoa test)", async () => {
    await runLargeDataTest();
  });
});
