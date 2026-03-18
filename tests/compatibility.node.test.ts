// test with python cryptography.fernet

import { execSync } from "node:child_process";
import { describe, expect, it } from "vitest";

import { Fernet } from "../lib/fernet";

// Remember to create a python virtual environment and install cryptography
const PYTHON_EXECUTABLE = "./.venv/bin/python3";
const REF_SCRIPT = "./tests/fernet_ref.py";

function pythonFernet(
  command: string,
  key: string,
  data: string,
  ttl?: number,
): string {
  let cmd = `${PYTHON_EXECUTABLE} ${REF_SCRIPT} ${command} --key "${key}"`;
  if (ttl !== undefined) {
    cmd += ` --ttl ${ttl}`;
  }

  cmd += ` --data "${data}"`;

  return execSync(cmd, { encoding: "utf-8" }).trim();
}

describe("Fernet Compatibility Tests", () => {
  it("should generate secrets that python can load", () => {
    const secret = Fernet.generateSecret();
    expect(() => pythonFernet("encrypt", secret, "test")).not.toThrow();
  });

  it("should be compatible: TS Encrypt -> Python Decrypt", async () => {
    const secret = Fernet.generateSecret();
    const fernet = new Fernet(secret);
    const message = "Hello from TypeScript!";

    const tsToken = await fernet.encrypt(message);
    const pyDecrypted = pythonFernet("decrypt", secret, tsToken);
    expect(pyDecrypted).toBe(message);
  });

  it("should be compatible: Python Encrypt -> TS Decrypt", async () => {
    const secret = Fernet.generateSecret();
    const fernet = new Fernet(secret);
    const message = "Hello from TypeScript!";

    const pyToken = pythonFernet("encrypt", secret, message);
    const tsDecrypted = await fernet.decrypt(pyToken);
    const tsDecryptedStr = new TextDecoder().decode(tsDecrypted);
    expect(tsDecryptedStr).toBe(message);
  });

  it("should respect TTL validation", async () => {
    const secret = Fernet.generateSecret();
    const fernet = new Fernet(secret);
    const message = "Hello world";

    const shortLivedToken = await fernet.encrypt(message);
    await expect(fernet.decrypt(shortLivedToken, 10)).resolves.not.toThrow();

    const pyTokenWithTTL = pythonFernet("encrypt", secret, message);
    const tsDecryptedTTL = await fernet.decrypt(pyTokenWithTTL, 60);
    expect(new TextDecoder().decode(tsDecryptedTTL)).toBe(message);
  });
});
