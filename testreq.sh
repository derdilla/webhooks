#!/usr/bin/bash

PAYLOAD='{"test": true}'
SECRET="test1234"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/.*= //')

curl -X POST http://0.0.0.0:3000/webhook/bpapp \
     -H "Content-Type: application/json" \
     -H "x-hub-signature-256: sha256=$SIGNATURE" \
     -d "$PAYLOAD"