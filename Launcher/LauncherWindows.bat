#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

function Write-Info  { Write-Host "[INFO] $args" -ForegroundColor Cyan }
function Write-Ok    { Write-Host "[ OK ] $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "[WARN] $args" -ForegroundColor Yellow }
function Write-Err   { Write-Host "[ERR ] $args" -ForegroundColor Red }

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue)
}

function Test-WingetPackage {
    param([string]$Id)
    $output = & winget list --id $Id --exact --source winget --accept-source-agreements --disable-interactivity 2>&1
    return ($LASTEXITCODE -eq 0 -and $output -notmatch "No installed package")
}

function Invoke-WingetInstall {
    param([string]$Id, [string]$Name)
    Write-Info "Installing $Name (winget id: $Id) ..."
    & winget install --id $Id --exact --source winget --silent `
        --disable-interactivity `
        --accept-source-agreements `
        --accept-package-agreements 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189) {
        Write-Ok "$Name installed (or already up to date)."
    } else {
        Write-Warn "$Name installation returned non-zero exit code: $LASTEXITCODE, please verify manually."
    }
}

# ============================================================
# Resolve project root (walk up to find DDOS/)
# ============================================================
function Resolve-ProjectRoot {
    param([string]$StartDir)
    if (-not $StartDir) { return $null }
    $dir = $StartDir
    for ($i = 0; $i -lt 8 -and $dir; $i++) {
        if (Test-Path (Join-Path $dir "DDOS")) {
            return $dir
        }
        $parent = Split-Path $dir -Parent
        if (-not $parent -or $parent -eq $dir) { break }
        $dir = $parent
    }
    return $null
}

# ============================================================
# Execute selected file (.py / .java / .c)
# ============================================================
function Invoke-TargetFile {
    param($File)

    $path = $File.FullPath
    $name = $File.Name

    Write-Info "Preparing to run: $path"

    switch ($File.Ext.ToLower()) {

        ".py" {
            if (-not (Test-Command "python")) {
                Write-Err "python not found, cannot run."
                return
            }
            # Avoid UnicodeEncodeError on Windows console
            $env:PYTHONIOENCODING = "utf-8"
            Write-Ok "Executing: python `"$path`""
            & python $path
        }

        ".java" {
            if (-not (Test-Command "javac") -or -not (Test-Command "java")) {
                Write-Err "javac/java not found, cannot run."
                return
            }
            # Extract public class name from source
            $content = Get-Content -Path $path -Raw -ErrorAction SilentlyContinue
            if ($content -match '(?m)^\s*public\s+(?:final\s+)?class\s+(\w+)') {
                $className = $matches[1]
            } else {
                $className = [IO.Path]::GetFileNameWithoutExtension($name)
            }
            $workDir = Split-Path $path -Parent
            Push-Location $workDir
            try {
                Write-Ok "Compiling: javac `"$path`""
                & javac $path
                if ($LASTEXITCODE -ne 0) {
                    Write-Err "javac compilation failed, exit code $LASTEXITCODE"
                    return
                }
                Write-Ok "Executing: java $className"
                & java $className
            } finally {
                Pop-Location
            }
        }

        ".c" {
            $content = Get-Content -Path $path -Raw -ErrorAction SilentlyContinue
            $isWindowsC = $content -match '#include\s*[<"]\s*(windows\.h|winsock2\.h)'
            $isLinuxC   = $content -match '#include\s*[<"]\s*(sys/socket\.h|pthread\.h|netinet/in\.h)'

            if ($isLinuxC -and -not $isWindowsC) {
                Write-Warn "This file appears to be Linux-only C code and cannot be compiled directly on Windows."
                Write-Info "Run it inside WSL: gcc -O3 -pthread -o udp_flood `"$path`" && ./udp_flood ..."
                return
            }

            if (-not (Test-Command "gcc")) {
                Write-Err "gcc not found, cannot compile."
                return
            }

            $exePath = [IO.Path]::ChangeExtension($path, ".exe")
            $workDir = Split-Path $path -Parent
            Push-Location $workDir
            try {
                if ($isWindowsC) {
                    Write-Ok "Compiling: gcc -O3 -o `"$exePath`" `"$path`" -lws2_32"
                    & gcc -O3 -finput-charset=UTF-8 -o $exePath $path -lws2_32
                } else {
                    Write-Ok "Compiling: gcc -O3 -o `"$exePath`" `"$path`""
                    & gcc -O3 -finput-charset=UTF-8 -o $exePath $path
                }
                if ($LASTEXITCODE -ne 0) {
                    Write-Err "gcc compilation failed, exit code $LASTEXITCODE"
                    return
                }
                Write-Ok "Executing: $exePath"
                & $exePath
            } finally {
                Pop-Location
            }
        }

        default {
            Write-Err "Unsupported file type: $($File.Ext)"
        }
    }
}

# ============================================================
# Scan + numbered menu
# ============================================================
function Start-RunMenu {
    param([string]$Root)

    $files = @()
    $dirs = @(
        @{ Path = Join-Path $Root "DDOS\Chinese"; Lang = "Chinese" },
        @{ Path = Join-Path $Root "DDOS\English"; Lang = "English" }
    )

    foreach ($d in $dirs) {
        if (-not (Test-Path $d.Path)) { continue }
        Get-ChildItem -Path $d.Path -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.py', '.c', '.java' } |
            ForEach-Object {
                $files += [PSCustomObject]@{
                    Name     = $_.Name
                    FullPath = $_.FullName
                    Lang     = $d.Lang
                    Ext      = $_.Extension
                }
            }
    }

    if ($files.Count -eq 0) {
        Write-Warn "No .py / .c / .java files found under $Root\DDOS."
        return
    }

    # Sort: Chinese first, English second; within same language by name
    $files = $files | Sort-Object Lang, Name

    Write-Host ""
    Write-Host "================ Select a file to run ================" -ForegroundColor Green
    for ($i = 0; $i -lt $files.Count; $i++) {
        $f = $files[$i]
        "{0,2}) {1,-32} ({2}, {3})" -f ($i + 1), $f.Name, $f.Lang, $f.Ext | Write-Host
    }
    Write-Host " 0) Exit" -ForegroundColor DarkGray
    Write-Host "======================================================" -ForegroundColor Green

    $selected = $null
    while (-not $selected) {
        $choice = Read-Host "[?] Enter number"
        if ($choice -eq "0") {
            Write-Info "Exited."
            return
        }
        $idx = 0
        if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 1 -and $idx -le $files.Count) {
            $selected = $files[$idx - 1]
        } else {
            Write-Err "Invalid input, enter 1-$($files.Count) or 0 to exit."
        }
    }

    Write-Host ""
    Invoke-TargetFile -File $selected
    Write-Host ""
    Write-Ok "File execution finished."
}

# ============================================================
# Stage 0: Prerequisites
# ============================================================
if (-not (Test-Command "winget")) {
    Write-Err "winget not found. Please install or update 'App Installer' from the Microsoft Store."
    exit 1
}

Write-Info "===== Stage 1: Detect installed components (no downloads) ====="

$missing = @()

$cReady = (Test-Command "gcc")
if ($cReady) {
    Write-Ok "C compiler (gcc) already present, skipping."
} else {
    Write-Warn "C compiler (gcc) missing."
    $missing += "c_toolchain"
}

$javaReady = (Test-Command "java") -and (Test-Command "javac")
if ($javaReady) {
    Write-Ok "Java (java/javac) already present, skipping."
} else {
    Write-Warn "Java missing (java or javac unavailable)."
    $missing += "java"
}

$pythonReady = (Test-Command "python") -and (Test-Command "pip")
if ($pythonReady) {
    Write-Ok "Python (python/pip) already present, skipping."
} else {
    Write-Warn "Python missing (python or pip unavailable)."
    $missing += "python"
}

$figletReady = (Test-Command "figlet") -or (Test-Command "piglet")
if ($figletReady) {
    Write-Ok "figlet or piglet already present, skipping."
} else {
    Write-Warn "figlet/piglet missing."
    $missing += "figlet"
}

# ------------------------------------------------------------
# Case A: everything present -> go straight to run menu
# ------------------------------------------------------------
if ($missing.Count -eq 0) {
    Write-Host ""
    Write-Ok "All target components already installed. Nothing to download."
    Write-Host ""
    try {
        if (Test-Command "figlet") { & figlet -f small "All Ready" }
        elseif (Test-Command "piglet") { & piglet "All Ready" }
        else { Write-Host "All Ready" }
    } catch { Write-Host "All Ready" }

    # Refresh PATH in case winget just installed something
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","Process")

    $startDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $projectRoot = Resolve-ProjectRoot -StartDir $startDir
    if ($projectRoot) {
        Write-Ok "Project root: $projectRoot"
        Start-RunMenu -Root $projectRoot
    } else {
        Write-Warn "DDOS subdirectory not found, skipping run menu."
        Write-Info "Place this script in the DDOS-Attack project root (the one containing DDOS/) and retry."
    }
    exit 0
}

# ------------------------------------------------------------
# Case B: missing components -> install
# ------------------------------------------------------------
Write-Info "Missing items: $($missing -join ', ')"
Write-Info "===== Stage 2: Install missing components ====="

foreach ($item in $missing) {
    switch ($item) {
        "c_toolchain" {
            Invoke-WingetInstall "WinDev.Mingw" "MinGW (C compiler)"
        }
        "java" {
            Invoke-WingetInstall "EclipseAdoptium.Temurin.21.JDK" "Java (Temurin JDK 21)"
        }
        "python" {
            Invoke-WingetInstall "Python.Python.3.12" "Python 3.12 + pip"
        }
        "figlet" {
            $installed = $false
            try {
                Invoke-WingetInstall "figlet.figlet" "figlet"
                $installed = Test-Command "figlet"
            } catch {}

            if (-not $installed) {
                Write-Info "figlet not available via winget, using Piglet (PowerShell port of figlet)."
                $pigletDir = "$env:USERPROFILE\.piglet"
                if (-not (Test-Path $pigletDir)) {
                    New-Item -ItemType Directory -Force -Path $pigletDir | Out-Null
                }
                $pigletUrl = "https://raw.githubusercontent.com/bcwood/Piglet/main/Piglet.ps1"
                try {
                    Invoke-WebRequest -Uri $pigletUrl -OutFile "$pigletDir\Piglet.ps1" -UseBasicParsing
                    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
                    if ($userPath -notlike "*$pigletDir*") {
                        [Environment]::SetEnvironmentVariable("PATH", "$userPath;$pigletDir", "User")
                    }
                    $env:Path = "$env:Path;$pigletDir"
                    Write-Ok "Piglet downloaded to $pigletDir and added to user PATH (takes effect in new terminals)."
                } catch {
                    Write-Warn "Piglet download failed: $($_.Exception.Message). You may install figlet4win manually later."
                }
            }
        }
    }
}

# ------------------------------------------------------------
# Installation summary
# ------------------------------------------------------------
Write-Host ""
Write-Host "================ Install summary ================" -ForegroundColor Green
$summaryItems = @(
    @{Name="gcc";     Check={gcc --version 2>&1 | Select-Object -First 1}},
    @{Name="java";    Check={java -version 2>&1 | Select-Object -First 1}},
    @{Name="javac";   Check={javac -version 2>&1}},
    @{Name="python";  Check={python --version 2>&1}},
    @{Name="pip";     Check={pip --version 2>&1}},
    @{Name="figlet";  Check={if (Test-Command "figlet") { figlet -v 2>&1 | Select-Object -First 1 } elseif (Test-Command "piglet") { "piglet (PowerShell)" } else { "not installed" }}}
)
foreach ($s in $summaryItems) {
    try {
        $ver = & $s.Check
        if ($null -eq $ver) { $ver = "not installed" }
    } catch { $ver = "not installed" }
    "{0,-10} : {1}" -f $s.Name, $ver
}
Write-Host "=================================================" -ForegroundColor Green

Write-Host ""
try {
    if (Test-Command "figlet") { & figlet -f small "Done" }
    elseif (Test-Command "piglet") { & piglet "Done" }
    else { Write-Host "All done." }
} catch { Write-Host "All done." }

# ============================================================
# Stage 3: Select a file to run
# ============================================================
Write-Host ""
Write-Info "===== Stage 3: Select a file to run ====="

# Refresh PATH after installation
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path","User") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path","Process")

$startDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$projectRoot = Resolve-ProjectRoot -StartDir $startDir

if (-not $projectRoot) {
    Write-Warn "DDOS subdirectory not found in current or script directory."
    Write-Info "Place this script in the DDOS-Attack project root (the one containing DDOS/) and retry."
    Write-Info "Or cd to the project root manually and re-run."
    exit 0
}

Write-Ok "Project root: $projectRoot"
Start-RunMenu -Root $projectRoot
