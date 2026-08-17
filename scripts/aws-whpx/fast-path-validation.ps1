$ErrorActionPreference = "Stop"

function Value-OrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

$Root = Value-OrDefault "GANTRY_TEST_ROOT" "C:\gantry"
$Gantry = Value-OrDefault "GANTRY_TEST_EXE" (Join-Path $Root "gantry-fastpath.exe")
$Kernel = Value-OrDefault "GANTRY_TEST_KERNEL" (Join-Path $Root "gantry-kernel-x86_64-tinyvm6c")
$Rootfs = Value-OrDefault "GANTRY_TEST_ROOTFS" (Join-Path $Root "nerdbox-rootfs-x86_64-noinline-plain-4k.erofs")
$Image = Value-OrDefault "GANTRY_TEST_IMAGE" (Join-Path $Root "debian-netprobe-nn-ca2-4k.erofs")
$ResultRoot = Value-OrDefault "GANTRY_TEST_RESULT_ROOT" (Join-Path $Root "validation-fast-path")
$Variant = Value-OrDefault "GANTRY_TEST_VARIANT" "baseline"
$Repeats = [int](Value-OrDefault "GANTRY_TEST_REPEATS" "5")
$MemoryMiB = [int](Value-OrDefault "GANTRY_TEST_MEMORY_MIB" "512")
$CPUCount = [int](Value-OrDefault "GANTRY_TEST_CPUS" "1")
$Network = Value-OrDefault "GANTRY_TEST_NET" "true"
$Profile = Value-OrDefault "GANTRY_TEST_PROFILE" "0"

foreach ($path in @($Gantry, $Kernel, $Rootfs, $Image)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "required file missing: $path" }
}

New-Item -ItemType Directory -Force -Path $ResultRoot | Out-Null
$env:GANTRY_HOME = Join-Path $ResultRoot "state-$Variant"
$env:GANTRY_BOOT_TIMING = "1"
if ($Profile -eq "1") {
    $env:GANTRY_BOOT_PROFILE = "1"
} else {
    Remove-Item Env:GANTRY_BOOT_PROFILE -ErrorAction SilentlyContinue
}

function Invoke-GantryBestEffort([string[]]$CommandArgs) {
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        & $script:Gantry @CommandArgs *> $null
        return $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $oldPreference }
}

function Milestone([string]$Text, [string]$Pattern) {
    $match = [regex]::Match($Text, $Pattern)
    if (-not $match.Success) { return [double]::NaN }
    return [double]::Parse($match.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture)
}

$rows = @()
for ($run = 1; $run -le $Repeats; $run++) {
    $name = "fast-$Variant-$run"
    $null = Invoke-GantryBestEffort @("stop", $name)
    $null = Invoke-GantryBestEffort @("delete", $name)
    $startLog = Join-Path $ResultRoot "$name.start.log"
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $oldPreference = $ErrorActionPreference
    try {
        # Gantry's boot timeline is intentionally written to stderr. Windows
        # PowerShell 5 wraps native stderr as ErrorRecord objects, so keep it
        # capturable without making a successful timing line terminate the run.
        $ErrorActionPreference = "Continue"
        & $Gantry start $name -kernel $Kernel -rootfs $Rootfs -image $Image -rw=false -mem "$MemoryMiB" -cpus "$CPUCount" -net="$Network" -process-isolation auto *> $startLog
        $startCode = $LASTEXITCODE
    }
    finally {
        $clock.Stop()
        $ErrorActionPreference = $oldPreference
    }
    if ($startCode -ne 0) { throw "gantry start $name failed with exit code $startCode" }

    $state = Join-Path $env:GANTRY_HOME $name
    $daemonLog = Join-Path $state "daemon.log"
    $text = Get-Content -Raw $daemonLog
    Copy-Item $daemonLog (Join-Path $ResultRoot "$name.daemon.log") -Force
    $workerLog = Join-Path $state "worker-vmm.log"
    if (Test-Path $workerLog -PathType Leaf) {
        $text += "`n" + (Get-Content -Raw $workerLog)
    }
    foreach ($leaf in @("worker-vmm.log", "console.log")) {
        $source = Join-Path $state $leaf
        if (Test-Path $source -PathType Leaf) {
            Copy-Item $source (Join-Path $ResultRoot "$name.$leaf") -Force
        }
    }

    $vcpu = Milestone $text 'guest vCPU entered WHPX\s+([0-9.]+) ms total'
    $virtio = Milestone $text 'guest first virtio-mmio access\s+([0-9.]+) ms total'
    $rootBlock = Milestone $text 'guest first root-block request\s+([0-9.]+) ms total'
    $vsock = Milestone $text 'guest first vsock traffic\s+([0-9.]+) ms total'
    $ready = Milestone $text 'guest RPC connected \(READY\)\s+([0-9.]+) ms'
    $rows += [pscustomobject]@{
        variant = $Variant
        profile = $Profile
        run = $run
        external_ms = [Math]::Round($clock.Elapsed.TotalMilliseconds, 3)
        daemon_ready_ms = $ready
        daemon_vcpu_ms = $vcpu
        vcpu_virtio_ms = $virtio - $vcpu
        virtio_root_ms = $rootBlock - $virtio
        root_vsock_ms = $vsock - $rootBlock
        vcpu_ready_ms = $ready - $vcpu
    }

    if ($Profile -eq "1") {
        Select-String -Path $daemonLog -Pattern "boot-timing:|boot-profile:"
        if (Test-Path $workerLog -PathType Leaf) {
            Select-String -Path $workerLog -Pattern "boot-timing:|boot-profile:"
        }
    }
    $null = Invoke-GantryBestEffort @("stop", $name)
    $null = Invoke-GantryBestEffort @("delete", $name)
}

$csv = Join-Path $ResultRoot "$Variant.csv"
$rows | Export-Csv -NoTypeInformation $csv
$rows | Format-Table -AutoSize
"results: $csv"
