$ErrorActionPreference = "Stop"

function Value-OrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

$Root = Value-OrDefault "GANTRY_TEST_ROOT" "C:\gantry"
$Gantry = Value-OrDefault "GANTRY_TEST_EXE" (Join-Path $Root "gantry-field.exe")
$StateRoot = Value-OrDefault "GANTRY_HOME" (Join-Path $Root "state-highmem")
$Sandbox = Value-OrDefault "GANTRY_TEST_SANDBOX" "highmem-22g"
$Kernel = Value-OrDefault "GANTRY_TEST_KERNEL" (Join-Path $Root "gantry-kernel-x86_64-tinyvm6c")
$Rootfs = Value-OrDefault "GANTRY_TEST_ROOTFS" (Join-Path $Root "nerdbox-rootfs-x86_64-noinline-plain-4k.erofs")
$Image = Value-OrDefault "GANTRY_TEST_IMAGE" (Join-Path $Root "debian-netprobe-nn-ca2-4k.erofs")
$MemoryMiB = [int](Value-OrDefault "GANTRY_TEST_MEMORY_MIB" "22528")
$CPUCount = [int](Value-OrDefault "GANTRY_TEST_CPUS" "4")
$TouchGiB = [int](Value-OrDefault "GANTRY_TEST_TOUCH_GIB" "5")

$env:GANTRY_HOME = $StateRoot

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

foreach ($path in @($Gantry, $Kernel, $Rootfs, $Image)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "required file missing: $path" }
}

$passed = $false
try {
    $null = Invoke-GantryBestEffort @("stop", $Sandbox)
    $null = Invoke-GantryBestEffort @("delete", $Sandbox)
    Invoke-Gantry @(
        "start", $Sandbox,
        "-kernel", $Kernel,
		"-rootfs", $Rootfs,
		"-image", $Image,
		"-mem", "$MemoryMiB",
        "-cpus", "$CPUCount",
        "-process-isolation", "auto"
    )

	$memTotalKiB = 0L
	$minimumKiB = [long]($MemoryMiB - 512) * 1024
	$memoryDeadline = [DateTime]::UtcNow.AddSeconds(60)
	$memoryClock = [Diagnostics.Stopwatch]::StartNew()
	do {
		$meminfo = & $Gantry exec $Sandbox -- awk '/^MemTotal:/ {print $2}' /proc/meminfo
		if ($LASTEXITCODE -ne 0) { throw "reading guest MemTotal failed with exit code $LASTEXITCODE" }
		foreach ($line in $meminfo) {
			if ("$line" -match '^\s*(\d+)\s*$') {
				$memTotalKiB = [long]$Matches[1]
			}
		}
		if ($memTotalKiB -ge $minimumKiB) { break }
		Start-Sleep -Milliseconds 100
	} while ([DateTime]::UtcNow -lt $memoryDeadline)
	$memoryClock.Stop()
	if ($memTotalKiB -lt $minimumKiB) {
		throw "guest MemTotal $memTotalKiB KiB is below expected minimum $minimumKiB KiB"
	}
	"PASS guest reports $memTotalKiB KiB from a $MemoryMiB MiB configuration after $([Math]::Round($memoryClock.Elapsed.TotalMilliseconds, 3)) ms"

    $workerBytes = 1024 * 1024 * 1024
    $workerCode = '$n=' + $workerBytes + '; $x="x"x$n; for($i=0;$i<$n;$i+=4096){substr($x,$i,1)="y"} sleep 5;'
    $workers = @()
    for ($index = 0; $index -lt $TouchGiB; $index++) {
        $workers += "perl -e '$workerCode' &"
    }
    $touchScript = ($workers -join ' ') + " wait; echo touched-workers=$TouchGiB"
    Invoke-Gantry @("exec", $Sandbox, "--", "sh", "-c", $touchScript)
    "PASS guest process touched $TouchGiB GiB, necessarily exercising RAM above the 512 MiB boot region"
    $passed = $true
}
finally {
    $null = Invoke-GantryBestEffort @("stop", $Sandbox)
    if ($passed) {
        $null = Invoke-GantryBestEffort @("delete", $Sandbox)
    }
}
