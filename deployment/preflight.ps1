param(
    [string]$EnvironmentFile = ".env.production",
    [Alias("SkipTests")]
    [switch]$SkipDatabaseCheck,
    [switch]$SkipDocker
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$environmentPath = Join-Path $projectRoot $EnvironmentFile
$failures = [System.Collections.Generic.List[string]]::new()

function Add-Failure([string]$Message) {
    $failures.Add($Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Add-Pass([string]$Message) {
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

Write-Host "Appora production release preflight"

$requiredFiles = @(
    "Dockerfile",
    "docker-compose.production.yml",
    "requirements.txt",
    "deployment/nginx.conf",
    "deployment/backup.ps1",
    "deployment/restore.ps1"
)
foreach ($relativePath in $requiredFiles) {
    if (Test-Path -LiteralPath (Join-Path $projectRoot $relativePath)) {
        Add-Pass "$relativePath is present"
    } else {
        Add-Failure "$relativePath is missing"
    }
}

if (-not (Test-Path -LiteralPath $environmentPath)) {
    Add-Failure "$EnvironmentFile is missing; copy .env.production.example and fill it privately"
} else {
    $settings = @{}
    foreach ($line in Get-Content -LiteralPath $environmentPath) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#") -or -not $trimmed.Contains("=")) {
            continue
        }
        $key, $value = $trimmed.Split("=", 2)
        $settings[$key.Trim()] = $value.Trim()
    }

    $requiredSettings = @(
        "APP_ENV", "SECRET_KEY", "DATABASE_URL", "REDIS_URL", "ADMIN_EMAIL", "ADMIN_PASSWORD",
        "PUBLIC_BASE_URL", "PRIVATE_UPLOAD_ROOT", "PASSWORD_RESET_MODE",
        "LEGAL_OPERATOR_NAME", "LEGAL_ADDRESS", "SUPPORT_EMAIL", "PRIVACY_EMAIL",
        "GRIEVANCE_OFFICER_NAME", "GRIEVANCE_EMAIL"
    )
    foreach ($key in $requiredSettings) {
        $value = $settings[$key]
        if (-not $value -or $value -match "replace-|your-domain|your-provider|Full name|Your registered|Your complete") {
            Add-Failure "$key is missing or still contains an example value"
        }
    }

    if ($settings["APP_ENV"] -ne "production") { Add-Failure "APP_ENV must be production" }
    if ($settings["FLASK_DEBUG"] -ne "false") { Add-Failure "FLASK_DEBUG must be false" }
    if ($settings["SESSION_COOKIE_SECURE"] -ne "true") { Add-Failure "SESSION_COOKIE_SECURE must be true" }
    if ($settings["TRUST_PROXY"] -ne "true") { Add-Failure "TRUST_PROXY must be true" }
    if ($settings["AUTO_MIGRATE"] -ne "false") { Add-Failure "AUTO_MIGRATE must be false" }
    if ($settings["PUBLIC_BASE_URL"] -notmatch "^https://") { Add-Failure "PUBLIC_BASE_URL must use HTTPS" }
    if ($settings["DATABASE_URL"] -notmatch "^postgresql(\+psycopg)?://") { Add-Failure "DATABASE_URL must use PostgreSQL" }
    if ($settings["REDIS_URL"] -notmatch "^rediss?://") { Add-Failure "REDIS_URL must use Redis" }
    if ($settings["PASSWORD_RESET_MODE"] -notin @("manual", "email")) { Add-Failure "PASSWORD_RESET_MODE must be manual or email" }
    if ($settings["PASSWORD_RESET_MODE"] -eq "email") {
        foreach ($key in @("SMTP_HOST", "SMTP_FROM_EMAIL")) {
            $value = $settings[$key]
            if (-not $value -or $value -match "replace-|your-domain|your-provider") {
                Add-Failure "$key is required when PASSWORD_RESET_MODE=email"
            }
        }
    }
    $secretKey = [string]$settings["SECRET_KEY"]
    $adminPassword = [string]$settings["ADMIN_PASSWORD"]
    if ($secretKey.Length -lt 32) { Add-Failure "SECRET_KEY must contain at least 32 characters" }
    if ($adminPassword.Length -lt 12) { Add-Failure "ADMIN_PASSWORD must contain at least 12 characters" }

    if ($failures.Count -eq 0) {
        Add-Pass "Production environment settings passed validation (secret values were not displayed)"
    }
}

foreach ($certificate in @("deployment/certs/fullchain.pem", "deployment/certs/privkey.pem")) {
    if (Test-Path -LiteralPath (Join-Path $projectRoot $certificate)) {
        Add-Pass "$certificate is present"
    } else {
        Add-Failure "$certificate is missing"
    }
}

if (-not $SkipDatabaseCheck) {
    $flask = Join-Path $projectRoot "env/Scripts/flask.exe"
    if (-not (Test-Path -LiteralPath $flask)) {
        Add-Failure "The local virtual environment is missing; create it and install requirements"
    } else {
        Push-Location $projectRoot
        try { & $flask --app app db check } finally { Pop-Location }
        if ($LASTEXITCODE -ne 0) { Add-Failure "Database models require a migration" } else { Add-Pass "Database migration state is current" }
    }
}

if (-not $SkipDocker) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Add-Failure "Docker is not installed or is not available on PATH"
    } else {
        Push-Location $projectRoot
        try {
            if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
                docker-compose --env-file $EnvironmentFile -f docker-compose.production.yml config --quiet
            } else {
                docker compose --env-file $EnvironmentFile -f docker-compose.production.yml config --quiet
            }
        } finally { Pop-Location }
        if ($LASTEXITCODE -ne 0) { Add-Failure "Docker Compose configuration is invalid" } else { Add-Pass "Docker Compose configuration is valid" }
    }
}

if ($failures.Count -gt 0) {
    Write-Host "Preflight found $($failures.Count) item(s) that must be fixed before launch." -ForegroundColor Yellow
    exit 1
}

Write-Host "Production release preflight passed." -ForegroundColor Green
