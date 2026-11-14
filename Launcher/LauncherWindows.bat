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

# ============================================================
# 新增：项目根目录定位
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
# 新增：执行选定文件（.py / .java / .c）
# ============================================================
function Invoke-TargetFile {
    param($File)

    $path = $File.FullPath
    $name = $File.Name

    Write-Info "准备运行：$path"

    switch ($File.Ext.ToLower()) {

        ".py" {
            if (-not (Test-Command "python")) {
                Write-Err "未找到 python，无法运行。"
                return
            }
            # 避免中文 print 在 Windows 控制台报 UnicodeEncodeError
            $env:PYTHONIOENCODING = "utf-8"
            Write-Ok "执行: python `"$path`""
            & python $path
        }

        ".java" {
            if (-not (Test-Command "javac") -or -not (Test-Command "java")) {
                Write-Err "未找到 javac/java，无法运行。"
                return
            }
            # 从源码中提取 public class 名
            $content = Get-Content -Path $path -Raw -ErrorAction SilentlyContinue
            if ($content -match '(?m)^\s*public\s+(?:final\s+)?class\s+(\w+)') {
                $className = $matches[1]
            } else {
                $className = [IO.Path]::GetFileNameWithoutExtension($name)
            }
            $workDir = Split-Path $path -Parent
            Push-Location $workDir
            try {
                Write-Ok "编译: javac `"$path`""
                & javac $path
                if ($LASTEXITCODE -ne 0) {
                    Write-Err "javac 编译失败，退出码 $LASTEXITCODE"
                    return
                }
                Write-Ok "执行: java $className"
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
                Write-Warn "该文件看起来是 Linux 专用 C 代码，Windows 下无法直接编译运行。"
                Write-Info "可在 WSL 中运行：gcc -O3 -pthread -o udp_flood `"$path`" && ./udp_flood ..."
                return
            }

            if (-not (Test-Command "gcc")) {
                Write-Err "未找到 gcc，无法编译。"
                return
            }

            $exePath = [IO.Path]::ChangeExtension($path, ".exe")
            $workDir = Split-Path $path -Parent
            Push-Location $workDir
            try {
                if ($isWindowsC) {
                    Write-Ok "编译: gcc -O3 -o `"$exePath`" `"$path`" -lws2_32"
                    & gcc -O3 -finput-charset=UTF-8 -o $exePath $path -lws2_32
                } else {
                    Write-Ok "编译: gcc -O3 -o `"$exePath`" `"$path`""
                    & gcc -O3 -finput-charset=UTF-8 -o $exePath $path
                }
                if ($LASTEXITCODE -ne 0) {
                    Write-Err "gcc 编译失败，退出码 $LASTEXITCODE"
                    return
                }
                Write-Ok "执行: $exePath"
                & $exePath
            } finally {
                Pop-Location
            }
        }

        default {
            Write-Err "不支持的文件类型：$($File.Ext)"
        }
    }
}

# ============================================================
# 新增：扫描 + 编号菜单
# ============================================================
function Start-RunMenu {
    param([string]$Root)

    $files = @()
    $dirs = @(
        @{ Path = Join-Path $Root "DDOS\Chinese"; Lang = "中文" },
        @{ Path = Join-Path $Root "DDOS\English"; Lang = "英文" }
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
        Write-Warn "在 $Root\DDOS 下未找到可运行的 .py / .c / .java 文件。"
        return
    }

    # 排序：中文在前，英文在后，同语言按文件名
    $files = $files | Sort-Object Lang, Name

    Write-Host ""
    Write-Host "================ 选择要运行的文件 ================" -ForegroundColor Green
    for ($i = 0; $i -lt $files.Count; $i++) {
        $f = $files[$i]
        "{0,2}) {1,-32} ({2}, {3})" -f ($i + 1), $f.Name, $f.Lang, $f.Ext | Write-Host
    }
    Write-Host " 0) 退出" -ForegroundColor DarkGray
    Write-Host "====================================================" -ForegroundColor Green

    $selected = $null
    while (-not $selected) {
        $choice = Read-Host "[?] 请输入编号"
        if ($choice -eq "0") {
            Write-Info "已退出。"
            return
        }
        $idx = 0
        if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 1 -and $idx -le $files.Count) {
            $selected = $files[$idx - 1]
        } else {
            Write-Err "无效输入，请输入 1-$($files.Count) 或 0 退出。"
        }
    }

    Write-Host ""
    Invoke-TargetFile -File $selected
    Write-Host ""
    Write-Ok "该文件已结束运行。"
}

# ============================================================
# 阶段 0：前置检查
# ============================================================
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

# ------------------------------------------------------------
# 情况 A：所有组件齐全 → 直接进入运行菜单
# ------------------------------------------------------------
if ($missing.Count -eq 0) {
    Write-Host ""
    Write-Ok "所有目标组件均已安装，无需下载任何内容。"
    Write-Host ""
    try {
        if (Test-Command "figlet") { & figlet -f small "All Ready" }
        elseif (Test-Command "piglet") { & piglet "All Ready" }
        else { Write-Host "All Ready" }
    } catch { Write-Host "All Ready" }

    # 刷新 PATH，防止 winget 装完后当前会话找不到
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","Process")

    $startDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $projectRoot = Resolve-ProjectRoot -StartDir $startDir
    if ($projectRoot) {
        Write-Ok "项目根目录：$projectRoot"
        Start-RunMenu -Root $projectRoot
    } else {
        Write-Warn "未找到 DDOS 子目录，跳过运行菜单。"
        Write-Info "请将本脚本放在 DDOS-Attack 项目根目录（含 DDOS/）后重试。"
    }
    exit 0
}

# ------------------------------------------------------------
# 情况 B：有缺失 → 安装
# ------------------------------------------------------------
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

# ------------------------------------------------------------
# 安装汇总
# ------------------------------------------------------------
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

# ============================================================
# 新增：阶段 3 —— 选择要运行的文件
# ============================================================
Write-Host ""
Write-Info "===== 阶段 3：选择要运行的文件 ====="

# 刷新 PATH，确保刚 winget 装完的程序能被找到
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path","User") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path","Process")

$startDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$projectRoot = Resolve-ProjectRoot -StartDir $startDir

if (-not $projectRoot) {
    Write-Warn "未在当前目录或脚本目录中找到 DDOS 子目录。"
    Write-Info "请将本脚本放在 DDOS-Attack 项目根目录（含 DDOS/）后重新运行。"
    Write-Info "或手动 cd 到项目根目录后再执行。"
    exit 0
}

Write-Ok "项目根目录：$projectRoot"
Start-RunMenu -Root $projectRoot
