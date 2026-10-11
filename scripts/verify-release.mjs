import fs from 'node:fs';
import { join } from 'node:path';
import { createHash, createPublicKey, verify } from 'node:crypto';

const [tag, releaseDir, outputFile] = process.argv.slice(2);
const fail = (message) => { throw new Error('REFUSING TO PUBLISH BETA FEED: ' + message); };
if (!tag || !releaseDir || !outputFile || !/^v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+$/.test(tag)) {
  fail('expected vMAJOR.MINOR.PATCH-beta.NUMBER and release download/output paths');
}
const version = tag.slice(1);
const name = 'MELMAN-Drop-' + version + '-x64-setup.exe';
const exePath = join(releaseDir, name);
const sigPath = exePath + '.sig';
const shaPath = join(releaseDir, 'SHA256.txt');
for (const p of [exePath, sigPath, shaPath]) {
  if (!fs.existsSync(p) || !fs.statSync(p).isFile()) fail('required release asset missing: ' + p);
}
const extras = fs.readdirSync(releaseDir).filter(n => n.toLowerCase().endsWith('.exe') && n !== name);
if (extras.length) fail('unexpected additional installer asset');

const keyText = Buffer.from(JSON.parse(fs.readFileSync('signing/tauri-updater-public.json','utf8')).pubkey, 'base64').toString('utf8');
const keyLine = keyText.trim().split(/\r?\n/).find(s => !s.startsWith('untrusted comment:'));
const publicKey = Buffer.from(keyLine ?? '', 'base64');
if (publicKey.length !== 42 || publicKey.subarray(0, 2).toString('ascii') !== 'Ed') fail('invalid pinned updater public key');
const key = createPublicKey({
  key: Buffer.concat([Buffer.from('302a300506032b6570032100','hex'), publicKey.subarray(10)]),
  format: 'der', type: 'spki'
});
let encodedSig = fs.readFileSync(sigPath, 'utf8').trim();
let decodedSig = encodedSig;
if (!encodedSig.startsWith('untrusted comment:')) {
  decodedSig = Buffer.from(encodedSig, 'base64').toString('utf8').trim();
}
const lines = decodedSig.split(/\r?\n/);
if (lines.length !== 4 || !lines[0].startsWith('untrusted comment:') || !lines[2].startsWith('trusted comment: ')) {
  fail('invalid minisign envelope');
}
const sig = Buffer.from(lines[1], 'base64');
const commentSig = Buffer.from(lines[3], 'base64');
if (sig.length !== 74 || commentSig.length !== 64 || !sig.subarray(2, 10).equals(publicKey.subarray(2, 10))) {
  fail('invalid signature or updater key ID');
}
const exe = fs.readFileSync(exePath);
const alg = sig.subarray(0, 2).toString('ascii');
const signedBytes = alg === 'ED' ? createHash('blake2b512').update(exe).digest() : alg === 'Ed' ? exe : fail('unsupported signer');
if (!verify(null, signedBytes, key, sig.subarray(10))) fail('installer signature is invalid');
const trusted = lines[2].slice('trusted comment: '.length);
if (!verify(null, Buffer.concat([sig.subarray(10), Buffer.from(trusted,'utf8')]), key, commentSig)) fail('signed release metadata is invalid');
if (!trusted.split('\t').includes('version:' + version)) fail('signature version does not match GitHub tag');
if (exe.subarray(0, 2).toString('ascii') !== 'MZ') fail('not a Windows executable');

const sha = createHash('sha256').update(exe).digest('hex');
const supplied = fs.readFileSync(shaPath,'utf8').trim();
if (!new RegExp('^' + sha + ' {2}' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$','i').test(supplied)) {
  fail('SHA256.txt does not match signed binary / filename');
}
const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
const release = event.release;
if (!release || release.draft || !release.prerelease || release.tag_name !== tag || release.target_commitish !== 'main') {
  fail('unexpected GitHub release metadata');
}
const existingPath = 'channels/beta.json';
if (fs.existsSync(existingPath)) {
  const old = JSON.parse(fs.readFileSync(existingPath, 'utf8')).version;
  const parsed = (s) => {
    const m = /^(\d+)\.(\d+)\.(\d+)-beta\.(\d+)$/.exec(s);
    return m ? m.slice(1).map(Number) : null;
  };
  const current = parsed(old), next = parsed(version);
  if (!current || !next) fail('unknown beta channel version format');
  for (let i = 0; i < 4; i++) {
    if (next[i] > current[i]) break;
    if (next[i] < current[i]) fail('would downgrade the beta channel from ' + old);
    if (i === 3) fail('same beta version already published');
  }
}
const url = 'https://github.com/Melman-code/melman-drop-releases/releases/download/' + tag + '/' + encodeURIComponent(name);
const notes = (release.body || 'Новая версия MELMAN Drop.').slice(0, 4500);
const feed = {
  version,
  notes,
  pub_date: release.published_at ?? new Date().toISOString(),
  platforms: { 'windows-x86_64': { url, signature: encodedSig } },
};

let verifiedUrl = false;
for (let attempt = 0; attempt < 4; attempt++) {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(45000), headers: { 'User-Agent': 'MELMAN-Drop-release-verifier' } });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const fetched = Buffer.from(await response.arrayBuffer());
    if (createHash('sha256').update(fetched).digest('hex') !== sha) throw new Error('public downloaded bytes do not match SHA-256');
    verifiedUrl = true;
    break;
  } catch (error) {
    if (attempt === 3) fail('public asset unreachable or invalid: ' + String(error).slice(0, 250));
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
}
if (!verifiedUrl) fail('public asset was not verified');
fs.writeFileSync(outputFile, JSON.stringify(feed, null, 2) + '\n', { flag: 'wx', encoding: 'utf8' });
console.log('SIGNED PUBLIC BETA VERIFIED:', tag, sha, 'manifest staged only');
