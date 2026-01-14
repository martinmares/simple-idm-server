#!/bin/bash

# Script pro generování argon2 hashe hesla
# Použití: ./scripts/hash_password.sh "moje_heslo"

if [ -z "$1" ]; then
    echo "Usage: $0 <password>"
    echo "Example: $0 'my_secure_password'"
    exit 1
fi

# Vyžaduje argon2 CLI tool
if ! command -v argon2 &> /dev/null; then
    echo "Error: argon2 CLI tool is not installed"
    echo ""
    echo "Install on macOS: brew install argon2"
    echo "Install on Ubuntu: sudo apt-get install argon2"
    exit 1
fi

PASSWORD="$1"
SALT=$(openssl rand -base64 16)

# Vygeneruj argon2 hash
HASH=$(echo -n "$PASSWORD" | argon2 "$SALT" -id -t 2 -m 14 -p 1 -l 32 -e)

echo "Password: $PASSWORD"
echo "Hash: $HASH"
echo ""
echo "Use this hash in your SQL INSERT statements:"
echo "  password_hash = '$HASH'"
