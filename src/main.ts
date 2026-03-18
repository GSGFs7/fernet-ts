import "./style.css";

import { Fernet } from "../lib/fernet";

async function setupFernetDemo() {
  const fernet = new Fernet();
  const secret = fernet.getSecret();

  const data = { message: "Ciallo～(∠・ω< )⌒★", timestamp: Date.now() };
  const token = await fernet.encryptJSON(data);
  const decrypted = await fernet.decryptJSON(token);

  return { secret, token, decrypted };
}

document.querySelector<HTMLDivElement>("#app")!.innerHTML = `
  <div>
    <h1>Vite + TypeScript + Fernet</h1>
    <div class="card">
      <h2>Fernet Demo</h2>
      <div id="fernet-output" style="text-align: left; font-family: monospace; font-size: 12px;">
        <p>Loading...</p>
      </div>
    </div>
    <p class="read-the-docs">
      Fernet symmetric encryption in the browser using Web Crypto API
    </p>
  </div>
`;

setupFernetDemo()
  .then(({ secret, token, decrypted }) => {
    const output = document.querySelector<HTMLDivElement>("#fernet-output")!;
    output.innerHTML = `
    <p><strong>Secret:</strong> ${secret}</p>
    <p><strong>Token:</strong> ${token.substring(0, 50)}...</p>
    <p><strong>Decrypted:</strong> ${JSON.stringify(decrypted)}</p>
  `;
  })
  .catch((err) => {
    console.error(err);
    const output = document.querySelector<HTMLDivElement>("#fernet-output")!;
    output.innerHTML = `<p style="color: red;">Error: ${err.message}</p>`;
  });
