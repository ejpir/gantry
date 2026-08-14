$ErrorActionPreference = "Stop"

function Value-OrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

$Root = Value-OrDefault "GANTRY_TEST_ROOT" "C:\gantry"
$Gantry = Value-OrDefault "GANTRY_TEST_EXE" (Join-Path $Root "gantry-field.exe")
$StateRoot = Value-OrDefault "GANTRY_HOME" (Join-Path $Root "state-smp")
$SandboxPrefix = Value-OrDefault "GANTRY_TEST_SANDBOX_PREFIX" "smp"
$Kernel = Value-OrDefault "GANTRY_TEST_KERNEL" (Join-Path $Root "gantry-kernel-x86_64-tinyvm6c")
$Rootfs = Value-OrDefault "GANTRY_TEST_ROOTFS" (Join-Path $Root "nerdbox-rootfs-x86_64-noinline-plain-4k.erofs")
$Image = Value-OrDefault "GANTRY_TEST_IMAGE" (Join-Path $Root "debian-netprobe-nn-ca2-4k.erofs")
$MemoryMiB = [int](Value-OrDefault "GANTRY_TEST_MEMORY_MIB" "1024")

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

function Test-SMP([int]$CPUCount) {
    $sandbox = "$script:SandboxPrefix-$CPUCount"
    $passed = $false
    try {
        $null = Invoke-GantryBestEffort @("stop", $sandbox)
        $null = Invoke-GantryBestEffort @("delete", $sandbox)
        Invoke-Gantry @(
            "start", $sandbox,
            "-kernel", $script:Kernel,
            "-rootfs", $script:Rootfs,
            "-image", $script:Image,
            "-mem", "$script:MemoryMiB",
            "-cpus", "$CPUCount",
            "-process-isolation", "auto"
        )

        $cpuInfo = & $script:Gantry exec $sandbox -- awk '/^processor[[:space:]]*:/ {n++} END {print n+0}' /proc/cpuinfo
        if ($LASTEXITCODE -ne 0) { throw "reading guest CPU count failed with exit code $LASTEXITCODE" }
        $onlineCPUs = -1
        foreach ($line in $cpuInfo) {
            if ("$line" -match '^\s*(\d+)\s*$') {
                $onlineCPUs = [int]$Matches[1]
            }
        }
        if ($onlineCPUs -ne $CPUCount) {
            throw "guest reports $onlineCPUs online CPUs from a $CPUCount-vCPU configuration"
        }

        $onlineMap = & $script:Gantry exec $sandbox -- cat /sys/devices/system/cpu/online
        if ($LASTEXITCODE -ne 0) { throw "reading guest CPU online map failed with exit code $LASTEXITCODE" }
        "PASS $sandbox reports $onlineCPUs CPUs online (map: $(($onlineMap -join ' ').Trim()))"

        $workerCode = '$x=0; for($i=0;$i<2000000;$i++){$x=($x+$i)&0x7fffffff} exit($x==0);'
        $workers = @()
        for ($index = 0; $index -lt $CPUCount; $index++) {
            $workers += "(taskset -c $index perl -e '$workerCode' && echo $index >> /tmp/gantry-smp-done) &"
        }
        $workScript = "set -e; command -v taskset >/dev/null; rm -f /tmp/gantry-smp-done; " +
            ($workers -join ' ') +
            " wait; test `$(wc -l < /tmp/gantry-smp-done) -eq $CPUCount; rm -f /tmp/gantry-smp-done; echo pinned-workers=$CPUCount"
        Invoke-Gantry @("exec", $sandbox, "--", "sh", "-c", $workScript)
        "PASS $sandbox completed one concurrent, affinity-pinned worker per vCPU"
        $passed = $true
    }
    finally {
        $null = Invoke-GantryBestEffort @("stop", $sandbox)
        if ($passed) {
            $null = Invoke-GantryBestEffort @("delete", $sandbox)
        }
    }
}

foreach ($path in @($Gantry, $Kernel, $Rootfs, $Image)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "required file missing: $path" }
}

Test-SMP 2
Test-SMP 4
