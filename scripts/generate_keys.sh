#!/bin/bash

# Script pro generování RSA klíčů pro JWT

set -e

KEYS_DIR="./keys"

echo "Generating RSA keys for JWT..."

# Vytvoř složku pro klíče
mkdir -p "$KEYS_DIR"

# Vygeneruj private key (RSA 2048-bit)
openssl genrsa -out "$KEYS_DIR/private.pem" 2048

# Vygeneruj public key z private key
openssl rsa -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/public.pem"

# Nastav správná oprávnění
chmod 600 "$KEYS_DIR/private.pem"
chmod 644 "$KEYS_DIR/public.pem"

echo "Keys generated successfully:"
echo "  Private key: $KEYS_DIR/private.pem"
echo "  Public key:  $KEYS_DIR/public.pem"
echo ""
echo "Make sure to keep the private key secure!"
