#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

fail() {
    echo -e "${RED}❌ FAILED:${NC} $1"
    exit 1
}

echo "🚀 Starting Ciph Integration Test"

command -v ciph >/dev/null 2>&1 || fail "ciph not found in PATH"

export CIPH_PASSWORD="testpassword123"

echo "[1/7] Creating 100MB test file"
dd if=/dev/urandom of=test_data.bin bs=1M count=100 status=none
ORIG_HASH=$(sha256sum test_data.bin | awk '{print $1}')

echo "[2/7] Encrypting with AES (chunk=4MB)"
ciph encrypt test_data.bin --cipher aes -c 4 > /dev/null
[ -f test_data.bin.ciph ] || fail "Encrypted file not created (AES)"

echo "[3/7] Renaming encrypted file"
mv test_data.bin.ciph hidden_payload.enc
rm -f test_data.bin

echo "[4/7] Decrypting with different chunk (16MB)"
ciph decrypt hidden_payload.enc -c 16 > /dev/null
[ -f test_data.bin ] || fail "Original filename not restored"

HASH_AES=$(sha256sum test_data.bin | awk '{print $1}')
[ "$HASH_AES" = "$ORIG_HASH" ] || fail "AES integrity check failed"

echo -e "${GREEN}✔ AES integrity verified${NC}"

echo "[5/7] Encrypting with ChaCha (chunk=8MB)"
ciph encrypt test_data.bin --cipher chacha -c 8 > /dev/null
[ -f test_data.bin.ciph ] || fail "Encrypted file not created (ChaCha)"

mv test_data.bin.ciph vault.blob
rm -f test_data.bin

echo "[6/7] Decrypting ChaCha with mismatched chunk (32MB)"
ciph decrypt vault.blob -c 32 > /dev/null
[ -f test_data.bin ] || fail "ChaCha filename restore failed"

HASH_CHACHA=$(sha256sum test_data.bin | awk '{print $1}')
[ "$HASH_CHACHA" = "$ORIG_HASH" ] || fail "ChaCha integrity check failed"

echo -e "${GREEN}✔ ChaCha integrity verified${NC}"

echo "[7/7] Cleanup"
rm -f test_data.bin vault.blob hidden_payload.enc
unset CIPH_PASSWORD

echo -e "${GREEN}🎉 ALL TESTS PASSED — CIPH IS SOLID${NC}"
