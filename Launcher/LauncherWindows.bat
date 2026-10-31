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
    Write-Info "安装 $Name (winget id: $Id) ..."
    & winget install --id $Id --exact --source winget --silent `
        --disable-interactivity `
        --accept-source-agreements `
        --accept-package-agreements 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189) {
        Write-Ok "$Name 安装完成（或已是最新）。"
    } else {
        Write-Warn "$Name 安装返回非零退出码: $LASTEXITCODE，请手动确认。"
    }
}

if (-not (Test-Command "winget")) {
    Write-Err "未找到 winget。请先安装或更新 Microsoft Store 中的“应用安装程序”（App Installer）。"
    exit 1
}

Write-Info "===== 阶段 1：检测已安装组件（不下载） ====="

$missing = @()

$cReady = (Test-Command "gcc")
if ($cReady) {
    Write-Ok "C 编译器 (gcc) 已存在，跳过。"
} else {
    Write-Warn "C 编译器 (gcc) 缺失。"
    $missing += "c_toolchain"
}

$javaReady = (Test-Command "java") -and (Test-Command "javac")
if ($javaReady) {
    Write-Ok "Java (java/javac) 已存在，跳过。"
} else {
    Write-Warn "Java 缺失（java 或 javac 不可用）。"
    $missing += "java"
}

$pythonReady = (Test-Command "python") -and (Test-Command "pip")
if ($pythonReady) {
    Write-Ok "Python (python/pip) 已存在，跳过。"
} else {
    Write-Warn "Python 缺失（python 或 pip 不可用）。"
    $missing += "python"
}

$figletReady = (Test-Command "figlet") -or (Test-Command "piglet")
if ($figletReady) {
    Write-Ok "figlet 或 piglet 已存在，跳过。"
} else {
    Write-Warn "figlet/piglet 缺失。"
    $missing += "figlet"
}

if ($missing.Count -eq 0) {
    Write-Host ""
    Write-Ok "所有目标组件均已安装，无需下载任何内容。"
    Write-Host ""
    try {
        if (Test-Command "figlet") { & figlet -f small "All Ready" }
        elseif (Test-Command "piglet") { & piglet "All Ready" }
        else { Write-Host "All Ready" }
    } catch { Write-Host "All Ready" }
    exit 0
}

Write-Info "待安装项：$($missing -join ', ')"

Write-Info "===== 阶段 2：安装缺失组件 ====="

foreach ($item in $missing) {
    switch ($item) {
        "c_toolchain" {
            Invoke-WingetInstall "WinDev.Mingw" "MinGW (C 编译器)"
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
                Write-Info "winget 源中 figlet 不可用，改用 Piglet（PowerShell 版 figlet）。"
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
                    Write-Ok "Piglet 已下载到 $pigletDir，并已加入用户 PATH（新开终端生效）。"
                } catch {
                    Write-Warn "Piglet 下载失败：$($_.Exception.Message)。可稍后手动安装 figlet4win。"
                }
            }
        }
    }
}

Write-Host ""
Write-Host "================ 安装汇总 ================" -ForegroundColor Green
$summaryItems = @(
    @{Name="gcc";     Check={gcc --version 2>&1 | Select-Object -First 1}},
    @{Name="java";    Check={java -version 2>&1 | Select-Object -First 1}},
    @{Name="javac";   Check={javac -version 2>&1}},
    @{Name="python";  Check={python --version 2>&1}},
    @{Name="pip";     Check={pip --version 2>&1}},
    @{Name="figlet";  Check={if (Test-Command "figlet") { figlet -v 2>&1 | Select-Object -First 1 } elseif (Test-Command "piglet") { "piglet (PowerShell)" } else { "未安装" }}}
)
foreach ($s in $summaryItems) {
    try {
        $ver = & $s.Check
        if ($null -eq $ver) { $ver = "未安装" }
    } catch { $ver = "未安装" }
    "{0,-10} : {1}" -f $s.Name, $ver
}
Write-Host "=========================================" -ForegroundColor Green

Write-Host ""
try {
    if (Test-Command "figlet") { & figlet -f small "Done" }
    elseif (Test-Command "piglet") { & piglet "Done" }
    else { Write-Host "全部完成。" }
} catch { Write-Host "全部完成。" }
