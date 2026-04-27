# Secure Auction Build Script (Windows)
# Usage: .\build_deploy.ps1

$DIST_DIR = "dist"
$BINARY_NAME = "secure_auction.exe"

Write-Host "--------------------------------------------------" -ForegroundColor Cyan
Write-Host "Starting Secure Build Process..." -ForegroundColor Cyan
Write-Host "--------------------------------------------------" -ForegroundColor Cyan

# 1. Cleanup old dist folder
if (Test-Path $DIST_DIR) {
    Write-Host "Cleaning up old $DIST_DIR folder..."
    Remove-Item -Path $DIST_DIR -Recurse -Force
}
New-Item -ItemType Directory -Path $DIST_DIR | Out-Null
New-Item -ItemType Directory -Path "$DIST_DIR/db" | Out-Null

# 2. Build Binary with security flags
Write-Host "Compiling binary (cmd/blind-auction)..."
# -s: Omit symbol table, -w: Omit DWARF debug info
go build -ldflags="-s -w" -o "$DIST_DIR/$BINARY_NAME" ./cmd/blind-auction/main.go

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

# 3. Copy only essential files
Write-Host "Copying essential files (Excluding docs, tests)..."
Copy-Item ".env.template" -Destination "$DIST_DIR/.env.template"
Copy-Item "db/schema.sql" -Destination "$DIST_DIR/db/schema.sql"

# 3.1 Hardening Database Directory Permissions (Windows)
# - /inheritance:r : 상속된 권한 제거 (모두 차단)
# - /grant:r "$($env:USERNAME):(OI)(CI)F" : 현재 사용자에게만 전체 권한 부여
Write-Host "Hardening database directory permissions..." -ForegroundColor Yellow
icacls "$DIST_DIR/db" /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null

# 4. Build helper tools
Write-Host "Compiling helper tool (seed_whitelist)..."
go build -ldflags="-s -w" -o "$DIST_DIR/seed_whitelist.exe" ./cmd/seed_whitelist/main.go

# 5. Create deployment guide
$Guide = @"
Secure Auction Deployment Guide
1. Copy .env.template to .env and set your APP_MASTER_SECRET_V1.
2. docs/ and tests/ folders are removed for security.
3. Database schema is in db/schema.sql.
"@
$Guide | Out-File -FilePath "$DIST_DIR/DEPLOY.txt"

Write-Host "--------------------------------------------------" -ForegroundColor Green
Write-Host "Secure Package Ready!" -ForegroundColor Green
Write-Host "Path: $PWD/$DIST_DIR" -ForegroundColor Green
Write-Host "Excluded: docs/, tests/, all source code (.go)"
Write-Host "--------------------------------------------------" -ForegroundColor Green
