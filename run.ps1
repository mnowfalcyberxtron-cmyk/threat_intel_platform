param(
    [switch]$SkipInstall,
    [switch]$StopExisting
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$VenvPython = Join-Path $ProjectRoot "venv\Scripts\python.exe"
$Requirements = Join-Path $ProjectRoot "requirements.txt"
$MainFile = Join-Path $ProjectRoot "main.py"
$EnvFile = Join-Path $ProjectRoot ".env"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[ERROR] Python venv not found at .\venv\Scripts\python.exe" -ForegroundColor Red
    Write-Host "Create it first:" -ForegroundColor Yellow
    Write-Host "  py -m venv venv" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $MainFile)) {
    Write-Host "[ERROR] main.py not found in project root." -ForegroundColor Red
    exit 1
}

Write-Host "[INFO] Project root: $ProjectRoot" -ForegroundColor Cyan
Write-Host "[INFO] Using venv python: $VenvPython" -ForegroundColor Cyan

$Port = "8001"
if (Test-Path $EnvFile) {
    $portLine = Get-Content $EnvFile | Where-Object { $_ -match '^\s*PORT\s*=' } | Select-Object -First 1
    if ($portLine) {
        $parts = $portLine -split "=", 2
        if ($parts.Count -eq 2) {
            $candidate = $parts[1].Trim()
            if ($candidate) { $Port = $candidate }
        }
    }
}

function Get-PortOwnerPid {
    param([int]$PortNumber)
    try {
        $conn = Get-NetTCPConnection -LocalPort $PortNumber -State Listen -ErrorAction Stop | Select-Object -First 1
        if ($conn -and $conn.OwningProcess) { return [int]$conn.OwningProcess }
    } catch {}
    return $null
}

$PortInt = 0
[void][int]::TryParse($Port, [ref]$PortInt)
if ($PortInt -gt 0) {
    $ExistingPid = Get-PortOwnerPid -PortNumber $PortInt
    if ($ExistingPid) {
        $Proc = Get-Process -Id $ExistingPid -ErrorAction SilentlyContinue
        $ProcName = if ($Proc) { $Proc.ProcessName } else { "unknown" }

        if ($StopExisting) {
            Write-Host "[WARN] Port $Port is in use by PID $ExistingPid ($ProcName). Stopping it..." -ForegroundColor Yellow
            Stop-Process -Id $ExistingPid -Force
            Start-Sleep -Milliseconds 400
        } else {
            Write-Host "[ERROR] Port $Port is already in use by PID $ExistingPid ($ProcName)." -ForegroundColor Red
            Write-Host "Close the old app or run:" -ForegroundColor Yellow
            Write-Host "  Stop-Process -Id $ExistingPid -Force" -ForegroundColor Yellow
            Write-Host "Then start again with .\run.ps1" -ForegroundColor Yellow
            Write-Host "Or auto-stop it with: .\run.ps1 -StopExisting" -ForegroundColor Yellow
            exit 1
        }
    }
}

if (-not $SkipInstall) {
    if (Test-Path $Requirements) {
        Write-Host "[INFO] Installing dependencies from requirements.txt ..." -ForegroundColor Cyan
        & $VenvPython -m pip install -r $Requirements
    }
    else {
        Write-Host "[WARN] requirements.txt not found, skipping dependency installation." -ForegroundColor Yellow
    }
}
else {
    Write-Host "[INFO] SkipInstall enabled, dependency installation skipped." -ForegroundColor Yellow
}

Write-Host "[INFO] Starting CyberXTron TIP ..." -ForegroundColor Green
Write-Host "[INFO] Dashboard: http://localhost:$Port/" -ForegroundColor Green
Write-Host "[INFO] API Docs : http://localhost:$Port/api/docs" -ForegroundColor Green
Write-Host ""

# Force current process env so Python uses this port even if shell has stale PORT value
$env:PORT = $Port
$env:OPENROUTER_HTTP_REFERER = "http://localhost:$Port"

& $VenvPython $MainFile
