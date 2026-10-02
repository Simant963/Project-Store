param(
    [Parameter(Mandatory=$true)][string]$DatabaseBackup,
    [Parameter(Mandatory=$true)][string]$UploadsBackup,
    [Parameter(Mandatory=$true)][string]$Confirmation
)

$ErrorActionPreference = "Stop"
if ($Confirmation -ne "RESTORE-APPORA") {
    throw "Restoration cancelled. Pass -Confirmation RESTORE-APPORA to continue."
}
$databasePath = (Resolve-Path -LiteralPath $DatabaseBackup).Path
$uploadsPath = (Resolve-Path -LiteralPath $UploadsBackup).Path

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$databaseUrl = (Get-Content -LiteralPath (Join-Path $projectRoot ".env.production") |
    Where-Object { $_ -match '^DATABASE_URL=' } | Select-Object -First 1) -replace '^DATABASE_URL=', ''
if (-not $databaseUrl) { throw "DATABASE_URL is missing from .env.production" }
$env:APPORA_RESTORE_DATABASE_URL = $databaseUrl -replace '^postgresql\+psycopg://', 'postgresql://'
$composeJson = if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    docker-compose --env-file .env.production -f docker-compose.production.yml config --format json
} else {
    docker compose --env-file .env.production -f docker-compose.production.yml config --format json
}
$compose = $composeJson | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Could not read the Docker Compose project configuration." }
$network = "$($compose.name)_default"
$uploadsVolume = "$($compose.name)_private_uploads"
$databaseDirectory = Split-Path -Parent $databasePath
$databaseName = Split-Path -Leaf $databasePath
$uploadsDirectory = Split-Path -Parent $uploadsPath
$uploadsName = Split-Path -Leaf $uploadsPath
docker run --rm --network $network -e APPORA_RESTORE_DATABASE_URL `
    -e "APPORA_RESTORE_FILE=$databaseName" -v "${databaseDirectory}:/backup:ro" postgres:17-alpine `
    sh -c 'pg_restore -d "$APPORA_RESTORE_DATABASE_URL" --clean --if-exists --no-owner --no-acl --exit-on-error "/backup/$APPORA_RESTORE_FILE"'
if ($LASTEXITCODE -ne 0) { throw "Database restore failed; uploads were not changed." }
docker run --rm -e "APPORA_UPLOADS_FILE=$uploadsName" -v "${uploadsVolume}:/uploads" `
    -v "${uploadsDirectory}:/backup:ro" alpine:3.22 `
    sh -c 'find /uploads -mindepth 1 -delete && tar -C /uploads -xzf "/backup/$APPORA_UPLOADS_FILE"'
if ($LASTEXITCODE -ne 0) { throw "Upload restore failed." }
Remove-Item Env:APPORA_RESTORE_DATABASE_URL

Write-Host "Restore completed. Run the production preflight before reopening traffic."
