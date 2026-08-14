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
$IsolationPath = Join-Path (Join-Path $StateRoot $Sandbox) "isolation.json"

$env:GANTRY_HOME = $StateRoot
$env:GANTRY_BOOT_TIMING = "1"
$env:GANTRY_EXTRA_CMDLINE = "noapic"
$env:GANTRY_WHPX_PIC = "1"
$env:GANTRY_WHPX_PIC_NOPIT = "1"

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

function Assert-Isolation {
    if (-not (Test-Path $script:IsolationPath)) {
        throw "isolation report missing: $script:IsolationPath"
    }
    $report = Get-Content -Raw $script:IsolationPath | ConvertFrom-Json
    if ($report.topology -ne "split-vmm") {
        throw "expected split-vmm topology, got $($report.topology)"
    }
    if ($report.processBoundary -ne "enforced") {
        throw "expected enforced process boundary, got $($report.processBoundary)"
    }
    if (-not $report.vmmConfinement.applied) {
        throw "VMM worker confinement was not applied"
    }
    "PASS isolation: topology=split-vmm processBoundary=enforced"
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
    Invoke-Gantry @("exec", $Sandbox, "--", "sh", "-c", "grep -qx host-ro-replay /host/$roTag/host-ro.txt && grep -qx host-rw-replay /host/$rwTag/host-rw.txt")

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
    $requiredResult = Invoke-GantryBestEffort @(
        "start", $RequiredSandbox,
        "-kernel", $Kernel,
        "-rootfs", $Rootfs,
        "-image", $NetprobeImage,
        "-rw=false",
        "-mem", "128",
        "-cpus", "1",
        "-process-isolation", "required"
    )
    if ($requiredResult -eq 0) {
        throw "strict Windows isolation unexpectedly booted without enforced fs/net properties"
    }
    "PASS process-isolation=required fails closed on the partial Windows tier"

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
    $null = Invoke-GantryBestEffort @("stop", $Sandbox)
    if (Test-Path $TestRoot) { Remove-Item -Recurse -Force $TestRoot }
}
