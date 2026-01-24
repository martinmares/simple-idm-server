#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Simple IDM Migration & SQLx Prepare ===${NC}\n"

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo -e "${RED}ERROR: DATABASE_URL not set${NC}"
    echo "Set it in .env or export it:"
    echo "  export DATABASE_URL=postgres://user:password@localhost/simple_idm"
    exit 1
fi

echo -e "${GREEN}✓ DATABASE_URL: $DATABASE_URL${NC}\n"

# Run migrations
echo -e "${YELLOW}Running database migrations...${NC}"
cargo sqlx migrate run

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Migrations completed${NC}\n"
else
    echo -e "${RED}✗ Migration failed${NC}"
    exit 1
fi

# Prepare SQLx metadata
echo -e "${YELLOW}Generating SQLx metadata (.sqlx/)...${NC}"
cargo sqlx prepare -- --lib

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ SQLx metadata generated${NC}\n"
else
    echo -e "${RED}✗ SQLx prepare failed${NC}"
    exit 1
fi

echo -e "${GREEN}=== All done! ===${NC}"
echo "You can now build with: cargo build"
