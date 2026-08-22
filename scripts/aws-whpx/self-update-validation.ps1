$ErrorActionPreference = "Stop"

function Value-OrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

$Target = Value-OrDefault "GANTRY_TEST_UPDATE_EXE" "C:\gantry\gantry-self-update-test.exe"
if (-not (Test-Path $Target -PathType Leaf)) {
    throw "self-update test binary missing: $Target"
}

function Invoke-Capture([string[]]$Arguments) {
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $script:Target @Arguments 2>&1)
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
    $text = ($output | ForEach-Object { "$_" }) -join "`n"
    if ($code -ne 0) {
        throw "$script:Target $($Arguments -join ' ') failed with exit code $code`: $text"
    }
    return $text
}

$beforeOutput = Invoke-Capture -Arguments @("version")
$before = ($beforeOutput -split "`r?`n")[0]
if ($before -ne "gantry v0.0.0") {
    throw "unexpected pre-update version: $before"
}
$beforeHash = (Get-FileHash -Algorithm SHA256 $Target).Hash
$updateOutput = Invoke-Capture -Arguments @("update")
$updateOutput
$afterOutput = Invoke-Capture -Arguments @("version")
$after = ($afterOutput -split "`r?`n")[0]
$afterHash = (Get-FileHash -Algorithm SHA256 $Target).Hash

if ($after -eq "gantry v0.0.0") {
    throw "self-update left the old Windows binary installed"
}
if ($afterHash -eq $beforeHash) {
    throw "self-update did not replace the Windows executable"
}
if (-not $updateOutput.Contains("updated Gantry v0.0.0")) {
    throw "self-update did not report the installed transition: $updateOutput"
}

"PASS Windows self-update: $before -> $after (verified asset replaced in place)"
Remove-Item -Force $Target
# This test stamps the unreleased updater code as v0.0.0 and installs the
# latest public release. That destination may predate CleanupRetired, so clean
# the disposable source image here rather than imposing a forward-only cleanup
# contract on an older release.
$prefix = "." + [IO.Path]::GetFileName($Target) + ".old-"
Get-ChildItem -Force ([IO.Path]::GetDirectoryName($Target)) |
    Where-Object { -not $_.PSIsContainer -and $_.Name.StartsWith($prefix) } |
    Remove-Item -Force
