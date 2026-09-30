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

$databaseUrl = (Get-Content -LiteralPath (Join-Path $projectRoot ".env.production") |
    Where-Object { $_ -match '^DATABASE_URL=' } | Select-Object -First 1) -replace '^DATABASE_URL=', ''
if (-not $databaseUrl) { throw "DATABASE_URL is missing from .env.production" }
$env:APPORA_BACKUP_DATABASE_URL = $databaseUrl -replace '^postgresql\+psycopg://', 'postgresql://'
$compose = docker compose --env-file .env.production -f docker-compose.production.yml config --format json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Could not read the Docker Compose project configuration." }
$network = "$($compose.name)_default"
$uploadsVolume = "$($compose.name)_private_uploads"
$databaseName = Split-Path -Leaf $databaseFile
$uploadsName = Split-Path -Leaf $uploadsFile
docker run --rm --network $network -e APPORA_BACKUP_DATABASE_URL `
    -e "APPORA_BACKUP_FILE=$databaseName" -v "${backupRoot}:/backup" postgres:17-alpine `
    sh -c 'pg_dump "$APPORA_BACKUP_DATABASE_URL" -Fc -f "/backup/$APPORA_BACKUP_FILE"'
if ($LASTEXITCODE -ne 0 -or (Get-Item -LiteralPath $databaseFile).Length -eq 0) {
    Remove-Item -LiteralPath $databaseFile -Force -ErrorAction SilentlyContinue
    throw "Database backup failed; no usable dump was kept."
}
docker run --rm -v "${uploadsVolume}:/uploads:ro" -v "${backupRoot}:/backup" alpine:3.22 `
    tar -C /uploads -czf "/backup/$uploadsName" .
if ($LASTEXITCODE -ne 0 -or (Get-Item -LiteralPath $uploadsFile).Length -eq 0) {
    Remove-Item -LiteralPath $uploadsFile -Force -ErrorAction SilentlyContinue
    throw "Upload backup failed; no usable archive was kept."
}
Remove-Item Env:APPORA_BACKUP_DATABASE_URL

Write-Host "Database backup: $databaseFile"
Write-Host "Upload backup:   $uploadsFile"
