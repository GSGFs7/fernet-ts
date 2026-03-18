// test node and broswer environment compatibility

import { describe, expect, it } from "vitest";
import { Fernet } from "../lib/fernet";

const runCoreTest = async () => {
  const secret = Fernet.generateSecret();
  const fernet = new Fernet(secret);
  const message = "Hello Fernet!";

  const token = await fernet.encrypt(message);
  const decrypted = await fernet.decrypt(token);
  const decryptedtext = new TextDecoder().decode(decrypted);

  expect(decryptedtext).toBe(message);

  const jsonData = { cia: "llo", arr: [1, 2, 3] };
  const jsonToken = await fernet.encryptJSON(jsonData);
  const decryptedJSON = await fernet.decryptJSON(jsonToken);
  expect(decryptedJSON).toEqual(jsonData);
};

// NodeJS
describe("Fernet in Node.js environment", () => {
  it("should encrypt and decrypt correctly", async () => {
    await runCoreTest();
  });
});

/**
 * @vitest-environment jsdom
 */
describe("Fernet in Browser (jsdom) environment", () => {
  it("should encrypt and decrypt corretly", async () => {
    await runCoreTest();
  });
});
