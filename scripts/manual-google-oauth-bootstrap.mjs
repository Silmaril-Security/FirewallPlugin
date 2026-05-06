#!/usr/bin/env node

const clientId = process.env.GOOGLE_CLIENT_ID;
const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

if (!clientId || !clientSecret) {
  console.error("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET before running this script.");
  process.exit(1);
}

const scope = "https://www.googleapis.com/auth/gmail.readonly";

const deviceResponse = await postForm("https://oauth2.googleapis.com/device/code", {
  client_id: clientId,
  scope,
});

console.log("Open this URL and approve Gmail readonly access:");
console.log(deviceResponse.verification_url || deviceResponse.verification_url_complete);
console.log(`User code: ${deviceResponse.user_code}`);

const intervalMs = Number(deviceResponse.interval ?? 5) * 1000;
while (true) {
  await new Promise((resolve) => setTimeout(resolve, intervalMs));
  const tokenResponse = await postForm("https://oauth2.googleapis.com/token", {
    client_id: clientId,
    client_secret: clientSecret,
    device_code: deviceResponse.device_code,
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
  }, { tolerateErrors: true });

  if (tokenResponse.refresh_token) {
    console.log("\nRefresh token:");
    console.log(tokenResponse.refresh_token);
    process.exit(0);
  }

  if (tokenResponse.error === "authorization_pending" || tokenResponse.error === "slow_down") {
    continue;
  }

  console.error(JSON.stringify(tokenResponse, null, 2));
  process.exit(1);
}

async function postForm(url, fields, options = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  });
  const text = await response.text();
  const parsed = text ? JSON.parse(text) : {};
  if (!response.ok && !options.tolerateErrors) {
    throw new Error(`${url} failed (${response.status}): ${text}`);
  }
  return parsed;
}
