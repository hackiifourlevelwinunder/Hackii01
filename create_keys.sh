#!/bin/bash
# helper to create persistent ed25519 keys (optional)
mkdir -p data/keys
if [ ! -f data/keys/ed25519_priv.pem ]; then
  openssl genpkey -algorithm ED25519 -out data/keys/ed25519_priv.pem
  openssl pkey -in data/keys/ed25519_priv.pem -pubout -out data/keys/ed25519_pub.pem
  echo "Keys created in data/keys"
else
  echo "Keys already exist"
fi
