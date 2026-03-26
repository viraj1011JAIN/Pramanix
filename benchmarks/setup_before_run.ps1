# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
#
# benchmarks/setup_before_run.ps1
#
# Pre-flight setup for the Pramanix 100 M / 500 M Sovereign Audit.
#
# Run ONCE before any domain benchmark:
#
#   cd "C:\Users\hrm01\Pramanix test 2\Pramanix"
#   .\benchmarks\setup_before_run.ps1
#
# What this script does
# ---------------------
# 1. Verifies Python >= 3.13 is active (rejects Anaconda 3.12).
# 2. Confirms the project .venv is activated.
# 3. Checks all required packages are importable (pramanix, z3, psutil, orjson).
# 4. Creates the benchmarks/results/ output tree.
# 5. Checks disk (>= 25 GB free) and RAM (>= 4 GB free).
# 6. Checks Windows sleep is disabled (warns if not).
# 7. Prints a clear GO / NO-GO verdict.
#
# After this script exits 0, run the audit with:
#
#   python benchmarks/audit_pre_run_prep.py
#   python benchmarks/100m_orchestrator_fast.py --domain finance

$ErrorActionPreference = "Stop"

# ---- Paths ------------------------------------------------------------------

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$VenvPython  = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$ResultsDir  = Join-Path $ScriptDir "results"

# ---- Helpers ----------------------------------------------------------------

function Write-Header([string]$Title) {
    $line = "-" * 60
    Write-Host ""
    Write-Host $line
    Write-Host "  $Title"
    Write-Host $line
}

function Write-Ok([string]$Label) {
    Write-Host "  [OK] $Label" -ForegroundColor Green
}

function Write-No([string]$Label) {
    Write-Host "  [NO] $Label" -ForegroundColor Red
}

function Write-Warn([string]$Label) {
    Write-Host "  [!!] $Label" -ForegroundColor Yellow
}

$AllPass = $true

# ---- 1. Python version ------------------------------------------------------

Write-Header "1. PYTHON VERSION"

if (Test-Path $VenvPython) {
    $PythonExe = $VenvPython
} else {
    $PythonExe = "python"
}

try {
    $VerRaw    = & $PythonExe --version 2>&1
    $VerStr    = "$VerRaw" -replace "Python ", ""
    $Parts     = $VerStr.Split(".")
    $Major     = [int]$Parts[0]
    $Minor     = [int]$Parts[1]
    $VersionOk = ($Major -gt 3) -or ($Major -eq 3 -and $Minor -ge 13)

    if ($VersionOk) {
        Write-Ok "Python $VerStr  (need >= 3.13)"
    } else {
        Write-No "Python $VerStr  (need >= 3.13)"
        Write-Warn "FIX: Activate the .venv built with Python 3.13:"
        Write-Warn "     .\.venv\Scripts\Activate.ps1"
        $AllPass = $false
    }
    Write-Host "  Executable: $PythonExe"
} catch {
    Write-No "python not found or failed to run"
    Write-Warn "FIX: Run  .\.venv\Scripts\Activate.ps1  or install Python 3.13"
    $AllPass   = $false
    $PythonExe = $null
}

# ---- 2. Virtual environment -------------------------------------------------

Write-Header "2. VIRTUAL ENVIRONMENT"

$VenvExists    = Test-Path $VenvPython
$VenvActivated = ($null -ne $env:VIRTUAL_ENV) -and ($env:VIRTUAL_ENV -ne "")

if ($VenvExists) {
    Write-Ok ".venv exists at $ProjectRoot\.venv"
} else {
    Write-No ".venv not found at $ProjectRoot\.venv"
    Write-Warn "FIX: Create with Python 3.13 and install dependencies:"
    Write-Warn "  1. C:\Users\hrm01\AppData\Local\Programs\Python\Python313\python.exe -m venv .venv"
    Write-Warn "  2. .\.venv\Scripts\Activate.ps1"
    Write-Warn '  3. pip install -e ".[all]"'
    $AllPass = $false
}

if ($VenvActivated) {
    Write-Ok ".venv is activated (VIRTUAL_ENV=$env:VIRTUAL_ENV)"
} else {
    Write-Warn ".venv does not appear to be activated (VIRTUAL_ENV not set)"
    Write-Warn "FIX: Run  .\.venv\Scripts\Activate.ps1"
    # Non-fatal: we can still check imports via the venv python directly.
}

# ---- 3. Required packages ---------------------------------------------------

Write-Header "3. REQUIRED PACKAGES"

# Core packages (installed via pip install -e ".[all]")
$CorePackages = @("pramanix", "z3", "pydantic", "structlog")
# Benchmark-only packages not in pyproject.toml extras
$BenchPackages = @("psutil", "orjson")

$VersionSnippets = @{
    "pramanix"  = "import pramanix; print(getattr(pramanix,'__version__','dev'))"
    "z3"        = "import z3; print(z3.get_version_string())"
    "psutil"    = "import psutil; print(psutil.__version__)"
    "orjson"    = "import orjson; print(orjson.__version__)"
    "pydantic"  = "import pydantic; print(pydantic.__version__)"
    "structlog" = "import structlog; print(structlog.__version__)"
}

if ($null -ne $PythonExe) {
    # Auto-install benchmark-only packages if missing
    foreach ($pkg in $BenchPackages) {
        $snippet = $VersionSnippets[$pkg]
        $ver = & $PythonExe -c $snippet 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [..] $pkg not found - installing..." -ForegroundColor Yellow
            & $PythonExe -m pip install $pkg --quiet 2>&1 | Out-Null
        }
    }

    $PkgFail = $false
    foreach ($pkg in ($CorePackages + $BenchPackages)) {
        $snippet = $VersionSnippets[$pkg]
        try {
            $ver = & $PythonExe -c $snippet 2>&1
            if ($LASTEXITCODE -eq 0) {
                $padded = $pkg.PadRight(12)
                Write-Ok "$padded $ver"
            } else {
                Write-No "$pkg  not importable"
                $PkgFail = $true
            }
        } catch {
            Write-No "$pkg  error checking"
            $PkgFail = $true
        }
    }
    if ($PkgFail) {
        Write-Host ""
        Write-Warn 'FIX: With .venv activated, run:  pip install -e ".[all]"'
        $AllPass = $false
    }
} else {
    Write-Warn "SKIP: Cannot check packages - Python executable not found."
}

# ---- 4. Output directories --------------------------------------------------

Write-Header "4. OUTPUT DIRECTORIES"

$DirsToCreate = @(
    $ResultsDir,
    (Join-Path $ResultsDir "00_environment")
)

foreach ($dir in $DirsToCreate) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  [CREATED] $dir" -ForegroundColor Green
    } else {
        Write-Ok $dir
    }
}

# ---- 5. Disk space ----------------------------------------------------------

Write-Header "5. DISK SPACE  (need >= 25 GB free on C:)"

try {
    $Drive  = Get-PSDrive C -ErrorAction Stop
    $FreeGB = [math]::Round($Drive.Free / 1GB, 1)
    $UsedGB = [math]::Round($Drive.Used / 1GB, 1)
    $TotGB  = $FreeGB + $UsedGB
    $DiskOk = $FreeGB -ge 25

    if ($DiskOk) {
        Write-Ok "C: free $FreeGB GB of $TotGB GB"
    } else {
        Write-No "C: free $FreeGB GB of $TotGB GB  (need >= 25 GB)"
        $Needed = [math]::Ceiling(25 - $FreeGB)
        Write-Warn "FIX: Free up at least $Needed GB on C: before running."
        $AllPass = $false
    }
    Write-Host "  Note: each 100 M domain run writes ~7-20 GB of JSONL to benchmarks/results/"
} catch {
    Write-Warn "SKIP: Could not query C: drive."
}

# ---- 6. Available RAM -------------------------------------------------------

Write-Header "6. AVAILABLE RAM  (need >= 4 GB free)"

try {
    $OS     = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $FreeGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 1)
    $TotGB  = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 1)
    $RamOk  = $FreeGB -ge 4

    if ($RamOk) {
        Write-Ok "RAM free $FreeGB GB of $TotGB GB"
    } else {
        Write-No "RAM free $FreeGB GB of $TotGB GB  (need >= 4 GB)"
        Write-Warn "FIX: Close memory-heavy applications before running."
        $AllPass = $false
    }
    Write-Host "  Note: 18 workers x ~200 MiB each = ~3.6 GB minimum"
} catch {
    Write-Warn "SKIP: Could not query RAM."
}

# ---- 7. Windows sleep -------------------------------------------------------

Write-Header "7. WINDOWS SLEEP SETTING"

try {
    $PcfgOut  = & powercfg -query SCHEME_CURRENT SUB_SLEEP 2>&1 | Out-String
    $SleepOff = $PcfgOut -match "0x00000000"

    if ($SleepOff) {
        Write-Ok "Sleep/standby timeout is 0 (disabled) - safe for 12-15h runs"
    } else {
        Write-Warn "Sleep may be enabled - a 12-15 hour run could be interrupted."
        Write-Warn "To disable (run in an ADMIN PowerShell):"
        Write-Warn "  powercfg -change -standby-timeout-ac 0"
        Write-Warn "Re-enable after the run:"
        Write-Warn "  powercfg -change -standby-timeout-ac 30"
    }
} catch {
    Write-Warn "SKIP: powercfg not available."
}

# ---- Final verdict ----------------------------------------------------------

Write-Host ""
Write-Host ("=" * 60)
Write-Host "  VERDICT"
Write-Host ("=" * 60)

if ($AllPass) {
    Write-Host "  GO  [OK]  Environment is ready." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Cyan
    Write-Host "    1. Environment snapshot (once per machine):"
    Write-Host "         python benchmarks\audit_pre_run_prep.py"
    Write-Host ""
    Write-Host "    2. Smoke test (validates worker architecture, ~1 min):"
    Write-Host "         python benchmarks\_test_fast_e2e.py"
    Write-Host ""
    Write-Host "    3. Run 100 M domain benchmarks (one at a time, ~15h each):"
    Write-Host "         python benchmarks\100m_orchestrator_fast.py --domain finance"
    Write-Host "         python benchmarks\100m_orchestrator_fast.py --domain banking"
    Write-Host "         python benchmarks\100m_orchestrator_fast.py --domain fintech"
    Write-Host "         python benchmarks\100m_orchestrator_fast.py --domain healthcare"
    Write-Host "         python benchmarks\100m_orchestrator_fast.py --domain infra"
    Write-Host ""
    Write-Host ("=" * 60)
    exit 0
} else {
    Write-Host "  NO-GO [!!]  Fix the issues above, then re-run this script." -ForegroundColor Red
    Write-Host ("=" * 60)
    exit 1
}
