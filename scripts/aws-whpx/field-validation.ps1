$ErrorActionPreference = "Stop"

function Value-OrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

$Root = Value-OrDefault "GANTRY_TEST_ROOT" "C:\gantry"
$Gantry = Value-OrDefault "GANTRY_TEST_EXE" (Join-Path $Root "gantry-field.exe")
$StateRoot = Value-OrDefault "GANTRY_HOME" (Join-Path $Root "state-plaincmp")
$Sandbox = Value-OrDefault "GANTRY_TEST_SANDBOX" "plain"
$Kernel = Value-OrDefault "GANTRY_TEST_KERNEL" (Join-Path $Root "gantry-kernel-x86_64-tinyvm6c")
$Rootfs = Value-OrDefault "GANTRY_TEST_ROOTFS" (Join-Path $Root "nerdbox-rootfs-x86_64-noinline-plain-4k.erofs")
$NetprobeImage = Value-OrDefault "GANTRY_TEST_NETPROBE_IMAGE" (Join-Path $Root "debian-netprobe-nn-ca2-4k.erofs")
$TargetURL = Value-OrDefault "GANTRY_TEST_URL" "https://www.nn.nl/"
$TargetHost = ([Uri]$TargetURL).Host
$TestRoot = Join-Path $Root "field-replay"
$NetSandbox = "$Sandbox-netprobe"
$RequiredSandbox = "$Sandbox-required"
$OfflineSandbox = "$Sandbox-required-offline"
$IsolationPath = Join-Path (Join-Path $StateRoot $Sandbox) "isolation.json"

$env:GANTRY_HOME = $StateRoot
$env:GANTRY_BOOT_TIMING = "1"

function Invoke-Gantry([string[]]$CommandArgs) {
    & $script:Gantry @CommandArgs
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "gantry $($CommandArgs -join ' ') failed with exit code $code"
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

function Assert-Isolation([string]$Path = $script:IsolationPath, [string]$Mode = "auto") {
    if (-not (Test-Path $Path)) {
        throw "isolation report missing: $Path"
    }
    $report = Get-Content -Raw $Path | ConvertFrom-Json
    if ($report.topology -ne "split-net+split-vmm") {
        throw "expected split-net+split-vmm topology, got $($report.topology)"
    }
    if ($report.processBoundary -ne "enforced") {
        throw "expected enforced process boundary, got $($report.processBoundary)"
    }
    if (-not $report.networkConfinement.applied) {
        throw "network worker confinement was not applied"
    }
    if ($report.networkConfinement.mode -ne $Mode) {
        throw "network confinement mode $($report.networkConfinement.mode), want $Mode"
    }
    foreach ($propertyName in @("fs-read", "fs-write", "exec")) {
        $property = $report.networkConfinement.properties | Where-Object { $_.name -eq $propertyName }
        if ($null -eq $property -or $property.state -ne "enforced") {
            throw "network worker property $propertyName was not enforced: $($property | ConvertTo-Json -Compress)"
        }
    }
    $networkNote = $report.networkConfinement.notes | Where-Object { $_ -match "network-capable AppContainer token active" }
    if ($null -eq $networkNote) {
        throw "network confinement report did not verify the capability-bearing AppContainer"
    }
    if (-not $report.vmmConfinement.applied) {
        throw "VMM worker confinement was not applied"
    }
    if ($report.vmmConfinement.mode -ne $Mode) {
        throw "VMM confinement mode $($report.vmmConfinement.mode), want $Mode"
    }
    $exec = $report.vmmConfinement.properties | Where-Object { $_.name -eq "exec" }
    if ($null -eq $exec -or $exec.state -ne "enforced") {
        throw "VMM Job did not enforce exec denial: $($exec | ConvertTo-Json -Compress)"
    }
    foreach ($propertyName in @("fs-read", "fs-write", "net-dial")) {
        $property = $report.vmmConfinement.properties | Where-Object { $_.name -eq $propertyName }
        if ($null -eq $property -or $property.state -ne "enforced") {
            throw "AppContainer VMM property $propertyName was not enforced: $($property | ConvertTo-Json -Compress)"
        }
    }
    $brokerNote = $report.vmmConfinement.notes | Where-Object { $_ -match "WHPX partition.*trusted broker" }
    if ($null -eq $brokerNote) {
        throw "VMM confinement report did not disclose the WHPX broker trust boundary"
    }
    "PASS isolation: AppContainer network/device workers plus Job-confined WHPX broker; required properties enforced"
}

function Assert-OfflineIsolation([string]$Path) {
    if (-not (Test-Path $Path)) { throw "offline isolation report missing: $Path" }
    $report = Get-Content -Raw $Path | ConvertFrom-Json
    if ($report.topology -ne "split-vmm") {
        throw "expected offline split-vmm topology, got $($report.topology)"
    }
    if ($report.processBoundary -ne "enforced" -or -not $report.vmmConfinement.applied) {
        throw "offline split VMM confinement was not enforced"
    }
    "PASS process-isolation=required: offline split VMM confinement enforced"
}

foreach ($path in @($Gantry, $Kernel, $Rootfs, $NetprobeImage)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "required file missing: $path" }
}
$config = Join-Path (Join-Path $StateRoot $Sandbox) "sandbox.json"
if (-not (Test-Path $config -PathType Leaf)) {
    throw "saved sandbox configuration missing: $config"
}

$roTag = "replay-ro"
$rwTag = "replay-rw"
$roRoot = Join-Path $TestRoot "ro"
$rwRoot = Join-Path $TestRoot "rw"

try {
    $null = Invoke-GantryBestEffort @("stop", $Sandbox)
    Invoke-Gantry @("resume", $Sandbox)
    Assert-Isolation
    Invoke-Gantry @("exec", $Sandbox, "--", "sh", "-c", "echo replay-rw-layer >/root/gantry-field-replay; test -f /root/gantry-field-replay")
    "PASS guest exec and writable layer"

    $null = Invoke-GantryBestEffort @("share", "remove", "--force", $Sandbox, $roTag)
    $null = Invoke-GantryBestEffort @("share", "remove", "--force", $Sandbox, $rwTag)
    if (Test-Path $TestRoot) { Remove-Item -Recurse -Force $TestRoot }
    New-Item -ItemType Directory -Force $roRoot, $rwRoot | Out-Null
    [IO.File]::WriteAllText((Join-Path $roRoot "host-ro.txt"), "host-ro-replay")
    [IO.File]::WriteAllText((Join-Path $rwRoot "host-rw.txt"), "host-rw-replay")

    Invoke-Gantry @("share", "add", $Sandbox, "$roTag=$roRoot,ro")
    Invoke-Gantry @("share", "add", $Sandbox, "$rwTag=$rwRoot")
    Invoke-Gantry @("share", "ls", $Sandbox)
    Invoke-Gantry @("exec", $Sandbox, "--", "sh", "-c", "ls -la /host/$roTag >/dev/null && ls -la /host/$rwTag >/dev/null && grep -qx host-ro-replay /host/$roTag/host-ro.txt && grep -qx host-rw-replay /host/$rwTag/host-rw.txt")

    $readOnlyWrite = Invoke-GantryBestEffort @("exec", $Sandbox, "--", "touch", "/host/$roTag/denied.txt")
    if ($readOnlyWrite -eq 0) { throw "read-only share unexpectedly accepted a write" }
    "PASS read-only share rejects guest writes"

    Invoke-Gantry @("exec", $Sandbox, "--", "sh", "-c", "echo guest-rw-replay >/host/$rwTag/guest.txt; mv /host/$rwTag/guest.txt /host/$rwTag/guest-renamed.txt")
    $guestFile = Join-Path $rwRoot "guest-renamed.txt"
    if (([IO.File]::ReadAllText($guestFile)).Trim() -ne "guest-rw-replay") {
        throw "guest share write was not propagated to NTFS"
    }
    [IO.File]::WriteAllText((Join-Path $rwRoot "host-after.txt"), "host-after-replay")
    Invoke-Gantry @("exec", $Sandbox, "--", "grep", "-qx", "host-after-replay", "/host/$rwTag/host-after.txt")
    "PASS live shares: RO, RW, rename, host/guest propagation"

    Invoke-Gantry @("stop", $Sandbox)
    Invoke-Gantry @("resume", $Sandbox)
    Assert-Isolation
    Invoke-Gantry @("share", "ls", $Sandbox)
    Invoke-Gantry @("exec", $Sandbox, "--", "cat", "/host/$rwTag/host-after.txt")
    "PASS persistent shares survived a cold daemon restart"

    $null = Invoke-GantryBestEffort @("delete", $NetSandbox)
    Invoke-Gantry @(
        "start", $NetSandbox,
        "-kernel", $Kernel,
        "-rootfs", $Rootfs,
        "-image", $NetprobeImage,
        "-mem", "128",
        "-cpus", "1",
        "-process-isolation", "auto"
    )
    Invoke-Gantry @("exec", $NetSandbox, "--", "getent", "ahostsv4", $TargetHost)
    Invoke-Gantry @("exec", $NetSandbox, "--", "/usr/local/bin/netprobe", $TargetURL)
    "PASS DNS, TCP/443, TLS, and HTTP for $TargetURL"

    $null = Invoke-GantryBestEffort @("delete", $RequiredSandbox)
    Invoke-Gantry @(
        "start", $RequiredSandbox,
        "-kernel", $Kernel,
        "-rootfs", $Rootfs,
        "-image", $NetprobeImage,
        "-mem", "128",
        "-cpus", "1",
        "-process-isolation", "required"
    )
    $requiredIsolation = Join-Path (Join-Path $StateRoot $RequiredSandbox) "isolation.json"
    Assert-Isolation $requiredIsolation "required"
    Invoke-Gantry @("exec", $RequiredSandbox, "--", "getent", "ahostsv4", $TargetHost)
    Invoke-Gantry @("exec", $RequiredSandbox, "--", "/usr/local/bin/netprobe", $TargetURL)
    "PASS process-isolation=required: split network/VMM workers, DNS, TCP/443, TLS, and HTTP"
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    Invoke-Gantry @("stop", $RequiredSandbox)
    $stopwatch.Stop()
    if ($stopwatch.Elapsed.TotalSeconds -gt 5) {
        throw "Windows split-worker stop took $($stopwatch.Elapsed.TotalSeconds) seconds"
    }
    "PASS Windows split-worker stop completed in $([math]::Round($stopwatch.Elapsed.TotalMilliseconds)) ms"

    $null = Invoke-GantryBestEffort @("delete", $OfflineSandbox)
    Invoke-Gantry @(
        "start", $OfflineSandbox,
        "-kernel", $Kernel,
        "-rootfs", $Rootfs,
        "-image", $NetprobeImage,
        "-mem", "128",
        "-cpus", "1",
        "-net=false",
        "-process-isolation", "required"
    )
    $offlineIsolation = Join-Path (Join-Path $StateRoot $OfflineSandbox) "isolation.json"
    Assert-OfflineIsolation $offlineIsolation
    Invoke-Gantry @("exec", $OfflineSandbox, "--", "sh", "-c", "echo offline-split-ok; test ! -e /sys/class/net/eth0")

    "--- primary isolation.json"
    Get-Content $IsolationPath
    "--- primary daemon boot timings"
    Select-String -Path (Join-Path (Join-Path $StateRoot $Sandbox) "daemon.log") -Pattern "boot-timing:"
}
finally {
    $null = Invoke-GantryBestEffort @("share", "remove", "--force", $Sandbox, $roTag)
    $null = Invoke-GantryBestEffort @("share", "remove", "--force", $Sandbox, $rwTag)
    $null = Invoke-GantryBestEffort @("stop", $NetSandbox)
    $null = Invoke-GantryBestEffort @("delete", $NetSandbox)
    $null = Invoke-GantryBestEffort @("stop", $RequiredSandbox)
    $null = Invoke-GantryBestEffort @("delete", $RequiredSandbox)
    $null = Invoke-GantryBestEffort @("stop", $OfflineSandbox)
    $null = Invoke-GantryBestEffort @("delete", $OfflineSandbox)
    $null = Invoke-GantryBestEffort @("stop", $Sandbox)
    if (Test-Path $TestRoot) { Remove-Item -Recurse -Force $TestRoot }
}
