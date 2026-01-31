#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "🚀 Starting Ciph Integration Test..."

command -v ciph >/dev/null 2>&1 || {
    echo -e "${RED}FAILED: ciph not found in PATH${NC}"
    exit 1
}

export CIPH_PASSWORD="testpassword123"

echo "[1/5] Creating 10MB test file..."
dd if=/dev/urandom of=test_data.bin bs=1M count=10 status=none
ORIG_HASH=$(sha256sum test_data.bin | cut -d' ' -f1)

echo "[2/5] Encrypting..."
ciph encrypt test_data.bin > /dev/null

if [ ! -f test_data.bin.ciph ]; then
    echo -e "${RED}FAILED: Encrypted file not created${NC}"
    exit 1
fi

echo "[3/5] Renaming encrypted file..."
mv test_data.bin.ciph hidden.vault
rm test_data.bin

echo "[4/5] Decrypting..."
ciph decrypt hidden.vault > /dev/null

if [ ! -f test_data.bin ]; then
    echo -e "${RED}FAILED: Original filename was NOT restored${NC}"
    exit 1
fi

echo "[5/5] Verifying SHA-256 integrity..."
FINAL_HASH=$(sha256sum test_data.bin | cut -d' ' -f1)

if [ "$ORIG_HASH" = "$FINAL_HASH" ]; then
    echo -e "${GREEN}✅ SUCCESS: Integrity verified${NC}"
    echo "Original:  $ORIG_HASH"
    echo "Decrypted: $FINAL_HASH"
else
    echo -e "${RED}❌ FAILURE: Hash mismatch${NC}"
    exit 1
fi

rm -f test_data.bin hidden.vault
unset CIPH_PASSWORD

echo -e "${GREEN}🎉 All tests passed.${NC}"
