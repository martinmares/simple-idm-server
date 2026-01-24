#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ -z "$DATABASE_URL" ]; then
    echo -e "${RED}ERROR: DATABASE_URL not set${NC}"
    exit 1
fi

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage: $0 <version>${NC}"
    echo "Example: $0 18"
    echo ""
    echo "This will DELETE migrations >= version from _sqlx_migrations table"
    echo -e "${RED}WARNING: This allows re-running migrations!${NC}"
    exit 1
fi

VERSION=$1

echo -e "${YELLOW}=== Reset SQLx Migrations from version $VERSION ===${NC}\n"
echo -e "${RED}This will delete migrations >= $VERSION from _sqlx_migrations${NC}"
echo -e "${YELLOW}Press ENTER to continue or Ctrl+C to cancel...${NC}"
read

cargo sqlx database drop -y 2>/dev/null || true
cargo sqlx database create
cargo sqlx migrate run

echo -e "\n${GREEN}✓ Database recreated and all migrations applied${NC}"
