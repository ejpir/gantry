$ErrorActionPreference = "Stop"

function Value-OrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

$Root = Value-OrDefault "GANTRY_TEST_ROOT" "C:\gantry"
$Gantry = Value-OrDefault "GANTRY_TEST_EXE" (Join-Path $Root "gantry-field.exe")
$GuestTools = Value-OrDefault "GANTRY_TEST_GUEST" (Join-Path $Root "gantry-guest-x86_64")
$StateRoot = Value-OrDefault "GANTRY_HOME" (Join-Path $Root "state-ssh-devcontainers")
$Kernel = Value-OrDefault "GANTRY_TEST_CURRENT_KERNEL" (Join-Path $Root "gantry-kernel-x86_64")
$Rootfs = Value-OrDefault "GANTRY_TEST_CURRENT_ROOTFS" (Join-Path $Root "nerdbox-rootfs-x86_64.erofs")
$Image = Value-OrDefault "GANTRY_TEST_IDE_IMAGE" (Join-Path $Root "gantry-ide-image-x86_64.erofs")
$Sandbox = Value-OrDefault "GANTRY_TEST_SANDBOX" "ssh-devcontainers-whpx"
$Config = Join-Path (Join-Path $StateRoot $Sandbox) "sandbox.json"
$Log = Join-Path (Join-Path $StateRoot $Sandbox) "daemon.log"
$PaddedGuest = Join-Path $Root "gantry-guest-x86_64-padded"

$env:GANTRY_HOME = $StateRoot
$env:GANTRY_ARTIFACTS = $Root
$env:GANTRY_BOOT_TIMING = "1"

function Invoke-GantryCapture([string[]]$CommandArgs) {
    $oldPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5 wraps native stderr as ErrorRecord objects.
        $ErrorActionPreference = "Continue"
        $output = @(& $script:Gantry @CommandArgs 2>&1)
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
    $text = ($output | ForEach-Object { "$_" }) -join "`n"
    if ($code -ne 0) {
        throw "gantry $($CommandArgs -join ' ') failed with exit code $code`: $text"
    }
    return $text
}

function Invoke-Gantry([string[]]$CommandArgs) {
    $output = Invoke-GantryCapture $CommandArgs
    if (-not [string]::IsNullOrWhiteSpace($output)) { $output }
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

function Invoke-NativeCapture([string]$Executable, [string[]]$Arguments) {
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $Executable @Arguments 2>&1)
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
    $text = ($output | ForEach-Object { "$_" }) -join "`n"
    if ($code -ne 0) {
        throw "$Executable $($Arguments -join ' ') failed with exit code $code`: $text"
    }
    return $text
}

function Assert-Contains([string]$Label, [string]$Text, [string]$Needle) {
    if (-not $Text.Contains($Needle)) {
        throw "$Label`: output does not contain '$Needle': $Text"
    }
    "PASS ssh/devcontainers: $Label"
}

function Assert-Matches([string]$Label, [string]$Text, [string]$Pattern) {
    if ($Text -notmatch $Pattern) {
        throw "$Label`: output does not match '$Pattern': $Text"
    }
    "PASS ssh/devcontainers: $Label"
}

function Write-Config([object]$Value) {
    $json = $Value | ConvertTo-Json -Depth 100
    [IO.File]::WriteAllText($script:Config, "$json`n", (New-Object Text.UTF8Encoding($false)))
}

function Get-GuestBootID() {
    $output = Invoke-GantryCapture @("exec", $script:Sandbox, "--", "cat", "/proc/sys/kernel/random/boot_id")
    $matches = [regex]::Matches($output, "[0-9a-f]{8}-[0-9a-f-]{27}")
    if ($matches.Count -eq 0) { throw "could not read VM boot ID: $output" }
    return $matches[$matches.Count - 1].Value
}

function Invoke-GuestScript([string]$ScriptText) {
    # Windows PowerShell 5 rewrites quotes and newlines in native argv. Carry
    # complex Linux scripts as base64 so Gantry receives one unambiguous arg.
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ScriptText))
    return Invoke-GantryCapture @(
        "exec", $script:Sandbox, "--", "sh", "-c", "echo '$encoded' | base64 -d | sh"
    )
}

foreach ($path in @($Gantry, $GuestTools, $Kernel, $Rootfs, $Image)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "required file missing: $path" }
}
if ($null -eq (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
    throw "Windows OpenSSH client is not installed"
}

try {
    $null = Invoke-GantryBestEffort @("stop", $Sandbox)
    $null = Invoke-GantryBestEffort @("delete", $Sandbox)

    Invoke-Gantry @(
        "start", $Sandbox,
        "-kernel", $Kernel,
        "-rootfs", $Rootfs,
        "-ssh",
        "-devcontainers",
        "-mem", "4096",
        "-cpus", "2",
        "-disk-size", "2048",
        "-process-isolation", "auto"
    )

    $doctor = Invoke-GantryCapture @("ssh", "doctor", $Sandbox)
    $doctor
    Assert-Matches "doctor reports SSH enabled" $doctor "(?m)^SSH enabled\s+yes$"
    Assert-Matches "doctor reports Dev Containers enabled" $doctor "(?m)^Dev Containers\s+yes$"
    Assert-Matches "doctor finds Podman" $doctor "(?m)^Podman\s+yes$"

    $direct = Invoke-GantryCapture @("ssh", $Sandbox, "--", "/bin/echo", "GANTRY-DIRECT-SSH")
    Assert-Contains "direct gantry ssh command" $direct "GANTRY-DIRECT-SSH"

    Invoke-Gantry @("ssh", "setup")
    $managed = Invoke-NativeCapture "ssh.exe" @("-o", "BatchMode=yes", "$Sandbox.gantry", "/bin/echo", "GANTRY-MANAGED-SSH")
    Assert-Contains "managed *.gantry OpenSSH connection" $managed "GANTRY-MANAGED-SSH"

    $buildScript = @'
set -eux
exec 2>&1
context=$HOME/gantry-inner-image
rm -rf "$context"
mkdir -p "$context/rootfs"
for binary in /bin/sh /bin/echo /bin/cat; do
  target=$context/rootfs$binary
  mkdir -p "$(dirname "$target")"
  cp -L "$binary" "$target"
  ldd "$binary" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) { print $i; break } }'
done | sort -u | while IFS= read -r library; do
  target=$context/rootfs$library
  mkdir -p "$(dirname "$target")"
  cp -L "$library" "$target"
done
cat >"$context/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY rootfs /
CMD ["/bin/sh"]
DOCKERFILE
docker build -t localhost/gantry-field-inner:latest "$context"
docker volume rm -f gantry-field-volume >/dev/null 2>&1 || true
docker volume create gantry-field-volume >/dev/null
docker run --rm localhost/gantry-field-inner:latest /bin/echo GANTRY-NESTED-PODMAN
docker run --rm -v gantry-field-volume:/data localhost/gantry-field-inner:latest /bin/sh -c 'printf GANTRY-VOLUME-PERSISTED > /data/marker'
sudo mkdir -p /run/libpod/gantry-field-stale
sudo touch /run/libpod/gantry-field-stale/marker
sudo touch /var/lib/containers/gantry-field-persistent-marker
'@
    $nested = Invoke-GuestScript $buildScript
    Assert-Contains "offline nested Podman build and run" $nested "GANTRY-NESTED-PODMAN"

    $bootBefore = Get-GuestBootID
    Invoke-Gantry @("stop", $Sandbox)

    Copy-Item -Force $GuestTools $PaddedGuest
    $stream = [IO.File]::Open($PaddedGuest, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.SetLength(60 * 1024 * 1024) } finally { $stream.Dispose() }
    $configObject = Get-Content -Raw $Config | ConvertFrom-Json
    $configObject.guest_tools = $PaddedGuest
    Write-Config $configObject
    [IO.File]::WriteAllText($Log, "")

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    Invoke-Gantry @("resume", $Sandbox)
    $stopwatch.Stop()
    $early = Invoke-GantryCapture @("ssh", $Sandbox, "--", "/bin/echo", "GANTRY-EARLY-SSH")
    Assert-Contains "early SSH waits for asynchronous helper delivery" $early "GANTRY-EARLY-SSH"

    $readyMatch = Select-String -Path $Log -Pattern "guest RPC connected \(READY\)" | Select-Object -Last 1
    $deliveryMatch = Select-String -Path $Log -Pattern "guest tools delivered" | Select-Object -Last 1
    if ($null -eq $readyMatch -or $null -eq $deliveryMatch) {
        throw "missing readiness or guest-helper delivery evidence in $Log"
    }
    if ($readyMatch.LineNumber -ge $deliveryMatch.LineNumber) {
        throw "guest helper completed before readiness was published"
    }
    "PASS ssh/devcontainers: readiness returned in $($stopwatch.ElapsedMilliseconds) ms before padded helper delivery"

    $bootAfter = Get-GuestBootID
    if ($bootBefore -eq $bootAfter) { throw "VM boot ID did not change across stop/resume" }
    $restartScript = @'
set -eux
exec 2>&1
sudo mkdir -p /run/libpod/gantry-field-stale /run/gantry/podman
sudo touch /run/libpod/gantry-field-stale/marker
printf '%s\n' '__GANTRY_OLD_BOOT_ID__' | sudo tee /run/gantry/podman/boot-id >/dev/null
sudo test -e /run/libpod/gantry-field-stale/marker
env DOCKER_HOST=tcp://127.0.0.1:1 DOCKER_CONTEXT=bogus CONTAINER_HOST=tcp://127.0.0.1:2 XDG_RUNTIME_DIR=/missing \
  docker run --rm -v gantry-field-volume:/data localhost/gantry-field-inner:latest /bin/cat /data/marker
sudo test ! -e /run/libpod/gantry-field-stale
sudo test -e /var/lib/containers/gantry-field-persistent-marker
test "$(cat /proc/sys/kernel/random/boot_id)" = "$(sudo cat /run/gantry/podman/boot-id)"
'@
    $restartScript = $restartScript.Replace("__GANTRY_OLD_BOOT_ID__", $bootBefore)
    $restart = Invoke-GuestScript $restartScript
    Assert-Contains "nested images and volumes persist across resume" $restart "GANTRY-VOLUME-PERSISTED"
    "PASS ssh/devcontainers: boot transition clears only stale Podman run state and ignores inherited engine endpoints"

    Invoke-Gantry @("stop", $Sandbox)
    $configObject = Get-Content -Raw $Config | ConvertFrom-Json
    $configObject.PSObject.Properties.Remove("guest_tools")
    $configObject.PSObject.Properties.Remove("runtime")
    Write-Config $configObject

    Invoke-Gantry @("resume", $Sandbox)
    $legacy = Invoke-GantryCapture @("ssh", $Sandbox, "--", "/bin/echo", "GANTRY-LEGACY-FALLBACK")
    Assert-Contains "cwd-independent guest-helper fallback" $legacy "GANTRY-LEGACY-FALLBACK"
    Invoke-Gantry @("configure", $Sandbox, "-ssh", "-devcontainers")
    $normalized = Get-Content -Raw $Config | ConvertFrom-Json
    if ($normalized.runtime -ne "crun") {
        throw "configure did not normalize omitted runtime to crun"
    }
    $finalNested = Invoke-GantryCapture @(
        "exec", $Sandbox, "--", "env", "DOCKER_HOST=tcp://127.0.0.1:1",
        "docker", "run", "--rm", "localhost/gantry-field-inner:latest",
        "/bin/echo", "GANTRY-FINAL-NESTED"
    )
    Assert-Contains "nested runtime after legacy-profile resume" $finalNested "GANTRY-FINAL-NESTED"
    "PASS ssh/devcontainers: Windows WHPX SSH and Dev Containers field validation complete"
}
finally {
    $null = Invoke-GantryBestEffort @("ssh", "setup", "--remove")
    $null = Invoke-GantryBestEffort @("stop", $Sandbox)
    $null = Invoke-GantryBestEffort @("delete", $Sandbox)
    Remove-Item -Force -ErrorAction SilentlyContinue $PaddedGuest
}
