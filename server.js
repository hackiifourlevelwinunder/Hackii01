/**
 * Provably-fair RNG Server
 * - Node 18+ recommended
 * - Uses SQLite to persist rounds
 * - Generates/loads Ed25519 keypair (server identity)
 * - Endpoints:
 *   GET  /api/round/current
 *   POST /api/round/reveal   { clientSeed }
 *   GET  /api/round/history
 *
 * This is a demo; review before production use.
 */
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// DB setup
const DB_PATH = path.join(DATA_DIR, 'rounds.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS rounds (
  round_start INTEGER PRIMARY KEY,
  server_seed TEXT,
  server_seed_hash TEXT,
  server_pub TEXT,
  revealed INTEGER DEFAULT 0,
  predicted INTEGER,
  proof_hmac TEXT,
  proof_offset INTEGER,
  created_at INTEGER
);
`);

// Keypair (Ed25519) generation / load
const KEY_DIR = path.join(DATA_DIR, 'keys');
if (!fs.existsSync(KEY_DIR)) fs.mkdirSync(KEY_DIR, { recursive: true });
const PRIV_PATH = path.join(KEY_DIR, 'ed25519_priv.pem');
const PUB_PATH = path.join(KEY_DIR, 'ed25519_pub.pem');

function ensureKeypair() {
  if (fs.existsSync(PRIV_PATH) && fs.existsSync(PUB_PATH)) {
    const privPem = fs.readFileSync(PRIV_PATH);
    const pubPem = fs.readFileSync(PUB_PATH);
    return { privPem, pubPem };
  }
  // generate and persist
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  fs.writeFileSync(PRIV_PATH, privPem, { mode: 0o600 });
  fs.writeFileSync(PUB_PATH, pubPem);
  return { privPem, pubPem };
}
const { privPem, pubPem } = ensureKeypair();
console.log('Server identity public key (PEM):\n', pubPem.toString());

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname,'public')));

/* Config */
const ROUND_SECONDS = 60;
const REVEAL_AT = 20;

function nowSec(){ return Math.floor(Date.now()/1000); }
function minuteStart(ts){ return Math.floor(ts/60)*60; }

function getOrCreateRound(startSec) {
  const row = db.prepare('SELECT * FROM rounds WHERE round_start = ?').get(startSec);
  if (row) return row;
  // create new round
  const serverSeed = crypto.randomBytes(32).toString('hex');
  const serverSeedHash = crypto.createHash('sha256').update(serverSeed).digest('hex');
  // create ephemeral X25519 pub for commit display
  let serverPubHex = null;
  try {
    const { publicKey } = crypto.generateKeyPairSync('x25519');
    const raw = publicKey.export({ type:'spki', format:'der' });
    serverPubHex = raw.toString('hex');
  } catch(e){
    serverPubHex = crypto.randomBytes(32).toString('hex');
  }
  const now = nowSec();
  db.prepare(`INSERT INTO rounds (round_start, server_seed, server_seed_hash, server_pub, created_at) VALUES (?,?,?,?,?)`)
    .run(startSec, serverSeed, serverSeedHash, serverPubHex, now);
  return db.prepare('SELECT * FROM rounds WHERE round_start = ?').get(startSec);
}

// Helper to derive digit from HMAC hex (unsigned uint32 BE)
function deriveUnbiasedDigitFromHmacHex(hmacHex) {
  const buf = Buffer.from(hmacHex, 'hex');
  const UINT32_MAX = 0x100000000;
  const MAX_ACCEPT = UINT32_MAX - (UINT32_MAX % 10);
  for (let i=0;i+4<=buf.length;i+=4) {
    const val = buf.readUInt32BE(i);
    if (val < MAX_ACCEPT) {
      return { digit: val % 10, offset: i };
    }
  }
  return null;
}

// public API:
// GET /api/round/current
app.get('/api/round/current', (req, res) => {
  const now = nowSec();
  const start = minuteStart(now);
  const next = minuteStart(now + 60);
  // ensure rounds exist
  getOrCreateRound(start);
  getOrCreateRound(next);
  const r = db.prepare('SELECT round_start, server_seed_hash, server_pub, revealed, predicted, proof_hmac, proof_offset FROM rounds WHERE round_start = ?').get(start);
  res.json({
    roundStart: r.round_start,
    now,
    revealAt: r.round_start + REVEAL_AT,
    finalAt: r.round_start + ROUND_SECONDS,
    serverPub: r.server_pub,
    serverSeedHash: r.server_seed_hash,
    revealed: !!r.revealed
  });
});

// POST /api/round/reveal  { clientSeed: string }
// Only allowed at/after reveal time. Returns predicted, proof, serverSeed so client can verify.
app.post('/api/round/reveal', (req, res) => {
  const clientSeed = typeof req.body.clientSeed === 'string' ? req.body.clientSeed : '';
  const now = nowSec();
  const start = minuteStart(now);
  const r = getOrCreateRound(start);
  const revealTime = r.round_start + REVEAL_AT;
  if (now < revealTime) {
    return res.status(400).json({ error: 'too_early', revealAt: revealTime, now });
  }
  const dbRow = db.prepare('SELECT * FROM rounds WHERE round_start = ?').get(start);
  if (dbRow.revealed) {
    return res.json({
      roundStart: dbRow.round_start,
      predicted: dbRow.predicted,
      proof: { hmac: dbRow.proof_hmac, offset: dbRow.proof_offset },
      serverSeed: dbRow.server_seed
    });
  }
  // compose entropy
  const entropy = `serverPub:${dbRow.server_pub}|clientSeed:${clientSeed}|time:${now}`;
  // compute HMAC-SHA512
  const hmacHex = crypto.createHmac('sha512', dbRow.server_seed).update(entropy).digest('hex');
  const derived = deriveUnbiasedDigitFromHmacHex(hmacHex);
  const digit = derived ? derived.digit : Math.floor(Math.random()*10);
  // save
  db.prepare(`UPDATE rounds SET revealed=1, predicted=?, proof_hmac=?, proof_offset=? WHERE round_start = ?`)
    .run(digit, hmacHex, derived ? derived.offset : null, start);
  const updated = db.prepare('SELECT * FROM rounds WHERE round_start = ?').get(start);
  // sign proof with server ed25519 private key
  const sign = crypto.createSign('sha256');
  sign.update(hmacHex);
  sign.end();
  const priv = fs.readFileSync(path.join(__dirname,'data','keys','ed25519_priv.pem'));
  let signature = null;
  try {
    signature = sign.sign(priv).toString('hex');
  } catch(e){
    signature = null;
  }
  res.json({
    roundStart: updated.round_start,
    predicted: updated.predicted,
    proof: { hmac: updated.proof_hmac, offset: updated.proof_offset, signature },
    serverSeed: updated.server_seed
  });
});

// GET /api/round/history
app.get('/api/round/history', (req, res) => {
  const rows = db.prepare('SELECT round_start, revealed, predicted, proof_hmac FROM rounds ORDER BY round_start DESC LIMIT 50').all();
  res.json({ now: nowSec(), rounds: rows });
});

// serve client index.html at /
app.get('/', (req,res) => {
  res.sendFile(path.join(__dirname,'public','index.html'));
});

app.listen(PORT, ()=> console.log(`Provably-fair RNG server listening on ${PORT}`));
