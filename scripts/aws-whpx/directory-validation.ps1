$ErrorActionPreference = "Stop"

function Value-OrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

$Root = Value-OrDefault "GANTRY_TEST_ROOT" "C:\gantry"
$Gantry = Value-OrDefault "GANTRY_TEST_EXE" (Join-Path $Root "gantry-field.exe")
$StateRoot = Value-OrDefault "GANTRY_HOME" (Join-Path $Root "state-dirscan")
$Sandbox = Value-OrDefault "GANTRY_TEST_SANDBOX" "dirscan-windows"
$Kernel = Value-OrDefault "GANTRY_TEST_KERNEL" (Join-Path $Root "gantry-kernel-x86_64-tinyvm6c")
$Rootfs = Value-OrDefault "GANTRY_TEST_ROOTFS" (Join-Path $Root "nerdbox-rootfs-x86_64-noinline-plain-4k.erofs")
$Image = Value-OrDefault "GANTRY_TEST_IMAGE" (Join-Path $Root "debian-netprobe-nn-ca2-4k.erofs")
$Small = [int](Value-OrDefault "GANTRY_TEST_SMALL_DIR_FILES" "5000")
$Large = [int](Value-OrDefault "GANTRY_TEST_LARGE_DIR_FILES" "25000")
$Rounds = [int](Value-OrDefault "GANTRY_TEST_FIND_ROUNDS" "10")
$Stress = [int](Value-OrDefault "GANTRY_TEST_STRESS_FILES" "150000")
$StressRounds = [int](Value-OrDefault "GANTRY_TEST_STRESS_ROUNDS" "2")
$DirectLimitMicros = [long](Value-OrDefault "GANTRY_TEST_DIRECT_LIMIT_US" "30000000")
$ReuseExisting = (Value-OrDefault "GANTRY_TEST_REUSE_EXISTING" "0") -eq "1"
$HostRoot = Join-Path $Root "dirscan-host"
$GuestRoot = "/root/gantry-dirscan"
$ShareTag = "dirscan"

$env:GANTRY_HOME = $StateRoot
$env:GANTRY_EXTRA_CMDLINE = "noapic"
$env:GANTRY_WHPX_PIC = "1"
$env:GANTRY_WHPX_PIC_NOPIT = "1"

function Invoke-Gantry([string[]]$CommandArgs) {
    & $script:Gantry @CommandArgs
    if ($LASTEXITCODE -ne 0) {
        throw "gantry $($CommandArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Invoke-GantryCapture([string[]]$CommandArgs) {
    $output = & $script:Gantry @CommandArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "gantry $($CommandArgs -join ' ') failed with exit code $LASTEXITCODE`: $($output -join [Environment]::NewLine)"
    }
    return $output
}

function Invoke-GantryBestEffort([string[]]$CommandArgs) {
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        & $script:Gantry @CommandArgs *> $null
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
}

function Read-Metric([string]$Key, [string[]]$CommandArgs) {
    $value = $null
    foreach ($line in (Invoke-GantryCapture $CommandArgs)) {
        if ("$line" -match "^$([Regex]::Escape($Key))=(\d+)$") {
            $value = [long]$Matches[1]
        }
    }
    if ($null -eq $value) {
        throw "metric $Key missing from guest output"
    }
    return $value
}

function Count-Files([string]$Directory) {
    return Read-Metric "COUNT" @(
        "exec", $script:Sandbox, "--", "sh", "-c",
        'count=$(find "$1" -maxdepth 1 -type f | wc -l); echo COUNT=$count',
        "sh", $Directory
    )
}

function Measure-ScanMicros([string]$Directory) {
    return Read-Metric "SCAN_US" @(
        "exec", $script:Sandbox, "--", "sh", "-c",
        'directory=$1; rounds=$2; find "$directory" -maxdepth 1 -type f -name __gantry_not_present__ -print >/dev/null; start=$(date +%s%N); index=0; while [ "$index" -lt "$rounds" ]; do find "$directory" -maxdepth 1 -type f -name __gantry_not_present__ -print >/dev/null; index=$((index + 1)); done; end=$(date +%s%N); echo SCAN_US=$(((end - start) / 1000))',
        "sh", $Directory, "$script:Rounds"
    )
}

function Measure-DirectMicros([string]$Directory) {
    return Read-Metric "DIRECT_US" @(
        "exec", $script:Sandbox, "--", "sh", "-c",
        'target=$1/file-024999; start=$(date +%s%N); index=0; while [ "$index" -lt 10000 ]; do [ -f "$target" ] || exit 1; index=$((index + 1)); done; end=$(date +%s%N); echo DIRECT_US=$(((end - start) / 1000))',
        "sh", $Directory
    )
}

function Test-DirectoryPair([string]$Label, [string]$Directory) {
    $smallCount = Count-Files "$Directory/small"
    $largeCount = Count-Files "$Directory/large"
    if ($smallCount -ne $script:Small) {
        throw "$Label small count $smallCount, want $script:Small"
    }
    if ($largeCount -ne $script:Large) {
        throw "$Label large count $largeCount, want $script:Large"
    }

    $smallMicros = Measure-ScanMicros "$Directory/small"
    $largeMicros = Measure-ScanMicros "$Directory/large"
    $directMicros = Measure-DirectMicros "$Directory/large"
    $allowedMicros = $smallMicros * 8 + 500000

    $ratio = if ($smallMicros -eq 0) { "n/a" } else { "{0:F2}" -f ($largeMicros / $smallMicros) }
    $smallMs = "{0:F3}" -f ($smallMicros / 1000)
    $largeMs = "{0:F3}" -f ($largeMicros / 1000)
    $directMs = "{0:F3}" -f ($directMicros / 1000)
    "MEASURE Windows $Label`: $script:Rounds missing-name find scans: $script:Small files ${smallMs}ms, $script:Large files ${largeMs}ms (${ratio}x); 10k direct lookups ${directMs}ms"

    if ($largeMicros -gt $allowedMicros) {
        throw "$Label large-directory scans took $largeMicros us; scaling limit is $allowedMicros us"
    }
    if ($largeMicros -gt 10000000) {
        throw "$Label large-directory scans exceeded 10 seconds"
    }
    if ($directMicros -gt $script:DirectLimitMicros) {
        throw "$Label direct lookups took $directMicros us; limit is $script:DirectLimitMicros us"
    }

    "PASS Windows $Label`: $script:Rounds missing-name find scans: $script:Small files ${smallMs}ms, $script:Large files ${largeMs}ms (${ratio}x); 10k direct lookups ${directMs}ms"
}

function Test-StressDirectory([string]$Directory) {
    $output = Invoke-GantryCapture @(
        "exec", $script:Sandbox, "--", "sh", "-c",
        'directory=$1; expected=$2; rounds=$3; start=$(date +%s%N); round=1; while [ "$round" -le "$rounds" ]; do count=$(find "$directory" -maxdepth 1 -type f -print | wc -l); echo STRESS_ROUND=$round STRESS_COUNT=$count; [ "$count" -eq "$expected" ] || exit 91; round=$((round + 1)); done; end=$(date +%s%N); echo STRESS_COUNT=$count; echo STRESS_US=$(((end - start) / 1000))',
        "sh", $Directory, "$script:Stress", "$script:StressRounds"
    )
    $count = $null
    $elapsedMicros = $null
    foreach ($line in $output) {
        if ("$line" -match '^STRESS_COUNT=(\d+)$') { $count = [long]$Matches[1] }
        if ("$line" -match '^STRESS_US=(\d+)$') { $elapsedMicros = [long]$Matches[1] }
    }
    if ($count -ne $script:Stress -or $null -eq $elapsedMicros) {
        throw "stress metrics missing or invalid: count=$count elapsed_us=$elapsedMicros"
    }
    $elapsedMs = "{0:F3}" -f ($elapsedMicros / 1000)
    "PASS Windows live host share stress: $script:Stress files traversed for $script:StressRounds rounds (${elapsedMs}ms); control plane remained live"
}

foreach ($path in @($Gantry, $Kernel, $Rootfs, $Image)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "required file missing: $path" }
}

$passed = $false
try {
    $null = Invoke-GantryBestEffort @("share", "remove", "--force", $Sandbox, $ShareTag)
    $null = Invoke-GantryBestEffort @("stop", $Sandbox)
    if ($ReuseExisting) {
        Invoke-Gantry @("resume", $Sandbox)
    }
    else {
        $null = Invoke-GantryBestEffort @("delete", $Sandbox)
        if (Test-Path $HostRoot) { Remove-Item -Recurse -Force $HostRoot }

        Invoke-Gantry @(
            "start", $Sandbox,
            "-kernel", $Kernel,
            "-rootfs", $Rootfs,
            "-image", $Image,
            "-mem", "1024",
            "-cpus", "2",
            "-process-isolation", "auto"
        )

        $null = Invoke-GantryCapture @("exec", $Sandbox, "--", "sh", "-c", "command -v find >/dev/null; command -v seq >/dev/null; command -v xargs >/dev/null; command -v date >/dev/null")
        $null = Invoke-GantryCapture @("exec", $Sandbox, "--", "sh", "-c", 'rm -rf "$1"; mkdir -p "$1/small" "$1/large"', "sh", $GuestRoot)
        $null = Invoke-GantryCapture @(
            "exec", $Sandbox, "--", "sh", "-c",
            'root=$1; small=$2; large=$3; seq -f "$root/small/file-%06g" 0 $((small - 1)) | xargs touch; seq -f "$root/large/file-%06g" 0 $((large - 1)) | xargs touch',
            "sh", $GuestRoot, "$Small", "$Large"
        )

        foreach ($spec in @(@("small", $Small), @("large", $Large), @("stress", $Stress))) {
            $directory = Join-Path $HostRoot $spec[0]
            [IO.Directory]::CreateDirectory($directory) | Out-Null
            for ($index = 0; $index -lt $spec[1]; $index++) {
                $path = Join-Path $directory ("file-{0:D6}" -f $index)
                [IO.File]::Create($path).Dispose()
            }
            $hostCount = ([IO.Directory]::GetFiles($directory)).Length
            if ($hostCount -ne $spec[1]) {
                throw "host $($spec[0]) count $hostCount, want $($spec[1])"
            }
            "HOST Windows $($spec[0]) populated with $hostCount files"
        }
    }

    Invoke-Gantry @("share", "add", $Sandbox, "$ShareTag=$HostRoot")
    Test-StressDirectory "/host/$ShareTag/stress"
    Invoke-Gantry @("exec", $Sandbox, "--", "true")
    Test-DirectoryPair "guest writable layer" $GuestRoot
    Test-DirectoryPair "live host share" "/host/$ShareTag"
    Invoke-Gantry @("exec", $Sandbox, "--", "true")
    "RESULT: Windows WHPX large-directory validation passed"
    $passed = $true
}
finally {
    $null = Invoke-GantryBestEffort @("share", "remove", "--force", $Sandbox, $ShareTag)
    $null = Invoke-GantryBestEffort @("stop", $Sandbox)
    if ($passed) {
        $null = Invoke-GantryBestEffort @("delete", $Sandbox)
    }
    if ($passed -and (Test-Path $HostRoot)) { Remove-Item -Recurse -Force $HostRoot }
}
