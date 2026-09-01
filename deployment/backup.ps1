param([string]$OutputDirectory = "backups")

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$backupRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))
if (-not $backupRoot.StartsWith($projectRoot + [System.IO.Path]::DirectorySeparatorChar)) {
    throw "Backup directory must stay inside the project directory."
}
New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$databaseFile = Join-Path $backupRoot "appora-$stamp.dump"
$uploadsFile = Join-Path $backupRoot "appora-uploads-$stamp.tar.gz"

docker compose --env-file .env.production -f docker-compose.production.yml exec -T db `
    sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > $databaseFile
docker compose --env-file .env.production -f docker-compose.production.yml exec -T web `
    tar -C /data/appora/uploads -czf - . > $uploadsFile

Write-Host "Database backup: $databaseFile"
Write-Host "Upload backup:   $uploadsFile"
