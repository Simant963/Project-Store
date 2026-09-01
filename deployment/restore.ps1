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

Get-Content -AsByteStream -Raw -LiteralPath $databasePath | docker compose --env-file .env.production -f docker-compose.production.yml exec -T db `
    sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists'
Get-Content -AsByteStream -Raw -LiteralPath $uploadsPath | docker compose --env-file .env.production -f docker-compose.production.yml exec -T web `
    sh -c "find /data/appora/uploads -mindepth 1 -delete && tar -C /data/appora/uploads -xzf -"

Write-Host "Restore completed. Run the production preflight before reopening traffic."
