// End-to-end bidirectional interoperability test between nullbin-cli (Go)
// and Nulliance/nullbin-server (real Go API server + TypeScript/libsodium crypto).
//
// Usage:
//   node scripts/e2e_interop.mjs <nullbin-cli-bin> <nullbin-server-dir> <nullbin-server-bin>

import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [cliBin, serverDir, serverBin] = process.argv.slice(2);
if (!cliBin || !serverDir || !serverBin) {
  console.error('usage: node scripts/e2e_interop.mjs <nullbin-cli-bin> <nullbin-server-dir> <nullbin-server-bin>');
  process.exit(2);
}

const sodiumMod = await import(
  pathToFileURL(path.join(serverDir, 'node_modules', 'libsodium-wrappers-sumo', 'dist', 'modules-sumo-esm', 'libsodium-wrappers.mjs')).href
);
const sodium = sodiumMod.default;
await sodium.ready;

const formatMod = await import(pathToFileURL(path.join(serverDir, 'web', 'src', 'format.ts')).href);
const cryptoMod = await import(pathToFileURL(path.join(serverDir, 'web', 'src', 'crypto.ts')).href);
const linkMod = await import(pathToFileURL(path.join(serverDir, 'web', 'src', 'link.ts')).href);

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      s.close(() => resolve(addr.port));
    });
    s.on('error', reject);
  });
}

function runCLI(args, stdin = '') {
  return execFileSync(cliBin, args, {
    input: stdin,
    encoding: 'utf8',
    env: { ...process.env, NULLBIN_SERVER: '', NULLBIN_API: '' },
  });
}

async function jsUpload(baseURL, prepared, opts) {
  const body = {
    expires_in: opts.expiresIn ?? 3600,
    burn_after_reading: Boolean(opts.burn),
    total_size: prepared.totalSize,
  };
  if (opts.burn) body.burn_token = prepared.burnToken;
  if (opts.discussion && prepared.commentToken) body.comment_token = prepared.commentToken;

  const initResp = await fetch(`${baseURL}/api/v1/pastes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  assert.equal(initResp.status, 201, `init upload status: ${initResp.status}`);
  const created = await initResp.json();

  const parts = [];
  for await (const c of prepared.chunks()) parts.push(Buffer.from(c));
  const full = Buffer.concat(parts);
  assert.equal(full.length, prepared.totalSize);

  const CHUNK = 4 * 1024 * 1024;
  let n = 0;
  for (let off = 0; off < full.length; off += CHUNK) {
    const piece = full.subarray(off, Math.min(off + CHUNK, full.length));
    const putResp = await fetch(`${baseURL}/api/v1/pastes/${created.id}/chunks/${n++}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Nullbin-Upload-Token': created.upload_token,
      },
      body: piece,
    });
    assert.equal(putResp.status, 204, `chunk ${n - 1} status: ${putResp.status}`);
  }

  const finResp = await fetch(`${baseURL}/api/v1/pastes/${created.id}/finalize`, {
    method: 'POST',
    headers: { 'Nullbin-Upload-Token': created.upload_token },
  });
  assert.equal(finResp.status, 200, `finalize status: ${finResp.status}`);
  const frag = linkMod.encodeKeyFragment(sodium, prepared.fragmentKey, Boolean(opts.burn), null);
  return `${baseURL}/p/${created.id}#${frag}`;
}

async function jsDownloadAndDecrypt(viewURL, password = null) {
  const u = new URL(viewURL);
  const id = u.pathname.replace(/^\/p\//, '');
  const parsed = linkMod.parseKeyFragment(sodium, u.hash);
  assert.ok(parsed, `failed to parse fragment from ${viewURL}`);

  let resp;
  if (parsed.burn || parsed.recipient !== null) {
    const prefResp = await fetch(`${u.origin}/api/v1/pastes/${id}/prefix`);
    assert.equal(prefResp.status, 200, `prefix status: ${prefResp.status}`);
    const prefix = formatMod.parsePrefix(new Uint8Array(await prefResp.arrayBuffer()));
    const master = prefix.password
      ? cryptoMod.deriveKey(sodium, parsed.key, password, prefix.salt)
      : parsed.key.slice();
    const token = parsed.recipient !== null
      ? cryptoMod.recipientAccessToken(sodium, master, parsed.recipient)
      : cryptoMod.burnAccessToken(sodium, master);
    resp = await fetch(`${u.origin}/api/v1/pastes/${id}/read`, {
      method: 'POST',
      headers: { 'Nullbin-Burn-Token': token },
    });
  } else {
    resp = await fetch(`${u.origin}/api/v1/pastes/${id}`);
  }
  assert.equal(resp.status, 200, `download status: ${resp.status}`);
  const reader = new formatMod.ByteReader(resp.body);
  const opened = await cryptoMod.openPaste(sodium, reader, parsed.key, async () => password);
  let fileBytes = null;
  if (opened.file) {
    const chunks = [];
    for await (const c of opened.file) chunks.push(Buffer.from(c));
    fileBytes = Buffer.concat(chunks);
  }
  return { meta: opened.meta, file: fileBytes };
}

const workDir = mkdtempSync(path.join(os.tmpdir(), 'nullbin-e2e-'));
const dataDir = path.join(workDir, 'data');
const port = await freePort();
const baseURL = `http://127.0.0.1:${port}`;

const cleanEnv = Object.fromEntries(
  Object.entries(process.env).filter(([k]) => !k.startsWith('NULLBIN_')),
);

const serverProc = spawn(serverBin, [], {
  env: {
    ...cleanEnv,
    NULLBIN_LISTEN_ADDR: `127.0.0.1:${port}`,
    NULLBIN_DATA_DIR: dataDir,
    NULLBIN_API_ONLY: 'true',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverStderr = '';
serverProc.stderr.on('data', (d) => { serverStderr += d.toString(); });

try {
  // Wait for server health on /api/v1/version.
  let ready = false;
  for (let i = 0; i < 60; i++) {
    if (serverProc.exitCode !== null) break;
    try {
      const r = await fetch(`${baseURL}/api/v1/version`);
      if (r.status === 200) {
        ready = true;
        break;
      }
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  assert.ok(ready, `nullbin server failed to start in time (exit=${serverProc.exitCode}, stderr=${serverStderr})`);

  // === Direction 1: Go CLI -> real server -> JS/libsodium decrypt ===
  console.log('[1/6] Go CLI create text + discussion -> JS decrypt');
  const goTextOut = JSON.parse(
    runCLI(['create', '--server', baseURL, '--discussion', '--json'], 'Hello from Go CLI! 日本語 🔐'),
  );
  const jsDecText = await jsDownloadAndDecrypt(goTextOut.view_url);
  assert.equal(jsDecText.meta.text, 'Hello from Go CLI! 日本語 🔐');
  assert.equal(jsDecText.meta.discussion, true);

  // Delete via Go CLI (--url-stdin) and verify 404.
  runCLI(['delete', '--url-stdin', '--json'], `${goTextOut.delete_url}\n`);
  const afterDel = await fetch(`${baseURL}/api/v1/pastes/${goTextOut.id}`);
  assert.equal(afterDel.status, 404);

  console.log('[2/6] Go CLI create burn + Unicode NFC password -> JS decrypt');
  const pwNFD = 'cafe\u0301-interop-pass';
  const pwNFC = 'caf\u00e9-interop-pass';
  const goBurnOut = JSON.parse(
    runCLI(
      ['create', '--server', baseURL, '--text', 'Burn secret from Go', '--burn', '--password-stdin', '--json'],
      `${pwNFD}\n`,
    ),
  );
  const jsDecBurn = await jsDownloadAndDecrypt(goBurnOut.view_url, pwNFC);
  assert.equal(jsDecBurn.meta.text, 'Burn secret from Go');
  const afterBurn = await fetch(`${baseURL}/api/v1/pastes/${goBurnOut.id}/prefix`);
  assert.equal(afterBurn.status, 404);

  console.log('[3/6] Go CLI create 2-file stored ZIP -> JS decrypt');
  const f1 = path.join(workDir, 'alpha.txt');
  const f2 = path.join(workDir, 'beta.bin');
  writeFileSync(f1, 'alpha content\n');
  writeFileSync(f2, Buffer.alloc(70000, 0x5a));
  const goZipOut = JSON.parse(
    runCLI(['create', '--server', baseURL, '--text', 'Two files', '--file', f1, '--file', f2, '--json']),
  );
  const jsDecZip = await jsDownloadAndDecrypt(goZipOut.view_url);
  assert.equal(jsDecZip.meta.type, 'file');
  assert.equal(jsDecZip.meta.filename, '2 files.zip');
  assert.equal(jsDecZip.meta.mime, 'application/zip');
  assert.ok(jsDecZip.file.length > 70000);
  assert.equal(jsDecZip.file.readUInt32LE(0), 0x04034b50); // ZIP local header magic

  console.log('[4/6] Go CLI create recipients + list + JS open + Go revoke');
  const goRcptOut = JSON.parse(
    runCLI(['create', '--server', baseURL, '--text', 'Recipient paste', '--recipient-limits', '1,none,none', '--json']),
  );
  assert.equal(goRcptOut.recipient_urls.length, 3);
  const jsRcpt0 = await jsDownloadAndDecrypt(goRcptOut.recipient_urls[0]);
  assert.equal(jsRcpt0.meta.text, 'Recipient paste');
  const rcptList = JSON.parse(runCLI(['recipients', 'list', '--url-stdin', '--json'], `${goRcptOut.delete_url}\n`));
  assert.equal(rcptList.recipients[0].opens, 1);
  assert.equal(rcptList.recipients[1].opens, 0);
  assert.equal(rcptList.recipients[2].opens, 0);
  runCLI(['recipients', 'revoke', '--url-stdin', '--json', '1'], `${goRcptOut.delete_url}\n`);
  const revokedURL = new URL(goRcptOut.recipient_urls[1]);
  const revokedParsed = linkMod.parseKeyFragment(sodium, revokedURL.hash);
  const revokedToken = cryptoMod.recipientAccessToken(sodium, revokedParsed.key, revokedParsed.recipient);
  const revokedResp = await fetch(`${baseURL}/api/v1/pastes/${goRcptOut.id}/read`, {
    method: 'POST',
    headers: { 'Nullbin-Burn-Token': revokedToken },
  });
  assert.equal(revokedResp.status, 410);
  // Revoking the last active link deletes the whole paste (404).
  runCLI(['recipients', 'revoke', '--url-stdin', '--json', '2'], `${goRcptOut.delete_url}\n`);
  const allClosedResp = await fetch(`${baseURL}/api/v1/pastes/${goRcptOut.id}/prefix`);
  assert.equal(allClosedResp.status, 404);

  // === Direction 2: JS/libsodium encrypt -> real server -> Go CLI decrypt ===
  console.log('[5/6] JS encrypt burn + Unicode password -> Go CLI read');
  const jsPrepBurn = cryptoMod.preparePaste(sodium, {
    text: 'Hello from JS libsodium!',
    file: null,
    filename: null,
    mime: null,
    password: pwNFC,
    discussion: false,
  });
  const jsBurnURL = await jsUpload(baseURL, jsPrepBurn, { burn: true });
  const goReadBurn = JSON.parse(
    runCLI(['read', '--yes', '--password-stdin', '--json', jsBurnURL], `${pwNFD}\n`),
  );
  assert.equal(goReadBurn.text, 'Hello from JS libsodium!');
  assert.equal(goReadBurn.reads_remaining, 0);

  console.log('[6/6] JS encrypt multi-frame file (>64 KiB) -> Go CLI read --out-dir');
  const bigBytes = Buffer.alloc(85000);
  for (let i = 0; i < bigBytes.length; i++) bigBytes[i] = (i * 29 + 11) & 0xff;
  const jsPrepFile = cryptoMod.preparePaste(sodium, {
    text: 'JS multi-frame file',
    file: new Blob([bigBytes]),
    filename: 'from-js.bin',
    mime: 'application/octet-stream',
    password: '',
    discussion: false,
  });
  const jsFileURL = await jsUpload(baseURL, jsPrepFile, { burn: false });
  const outDir = path.join(workDir, 'out');
  mkdirSync(outDir, { recursive: true });
  const goReadFile = JSON.parse(
    runCLI(['read', '--url-stdin', '--out-dir', outDir, '--json'], `${jsFileURL}\n`),
  );
  assert.equal(goReadFile.text, 'JS multi-frame file');
  const saved = readFileSync(goReadFile.saved_path);
  assert.ok(saved.equals(bigBytes), 'saved file bytes mismatch');

  console.log('ALL 6 BIDIRECTIONAL E2E INTEROP SCENARIOS PASSED!');
} finally {
  serverProc.kill();
  rmSync(workDir, { recursive: true, force: true });
}
