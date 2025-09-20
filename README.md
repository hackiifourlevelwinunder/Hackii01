# Provably-Fair RNG Server (Demo)

This repository contains a demo provably-fair RNG server and client.

## Features
- Node.js + Express server
- SQLite (better-sqlite3) persistence for rounds
- Per-minute rounds with commit (serverSeedHash) and reveal
- Ed25519 server keypair for signing proofs (generated on first run)
- Client UI served from `/`

## Files
- `server.js` - main server
- `public/index.html` - client UI
- `package.json` - dependencies
- `data/` - runtime data (DB and keys) created at runtime

## Run locally
```bash
npm install
node server.js
```
Open `http://localhost:3000/`

## Deploy
- **Render / Railway / Heroku**: push this repo to GitHub and connect on the platform (set start command `npm start`).
- Ensure the `data/` directory is writable (platforms with ephemeral disks will lose it on restart; use managed DB for production).

## Security
This is a demo. Do not use in production without review. Keep server keys safe.

