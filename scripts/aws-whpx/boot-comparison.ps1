$ErrorActionPreference = "Stop"

function Value-OrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

$Root = Value-OrDefault "GANTRY_TEST_ROOT" "C:\gantry"
$Gantry = Value-OrDefault "GANTRY_TEST_EXE" (Join-Path $Root "gantry-field.exe")
$Qemu = Value-OrDefault "GANTRY_TEST_QEMU" (Join-Path $Root "validation-qemu-11.1.0\qemu-system-x86_64.exe")
$Kernel = Value-OrDefault "GANTRY_TEST_KERNEL" (Join-Path $Root "gantry-kernel-x86_64-tinyvm6c")
$Rootfs = Value-OrDefault "GANTRY_TEST_ROOTFS" (Join-Path $Root "nerdbox-rootfs-x86_64-noinline-plain-4k.erofs")
$Image = Value-OrDefault "GANTRY_TEST_IMAGE" (Join-Path $Root "debian-netprobe-nn-ca2-4k.erofs")
$ResultRoot = Value-OrDefault "GANTRY_TEST_RESULT_ROOT" (Join-Path $Root "validation-boot-comparison")
$MemoryList = (Value-OrDefault "GANTRY_TEST_MEMORY_LIST" "512,4096,16384,22528").Split(",") | ForEach-Object { [int]$_.Trim() }
$Repeats = [int](Value-OrDefault "GANTRY_TEST_REPEATS" "5")
$CPUCount = [int](Value-OrDefault "GANTRY_TEST_CPUS" "1")
$QemuTimeoutSeconds = [int](Value-OrDefault "GANTRY_TEST_QEMU_TIMEOUT_SECONDS" "30")
$VirtioMem = Value-OrDefault "GANTRY_TEST_VIRTIO_MEM" "1"

foreach ($path in @($Gantry, $Qemu, $Kernel, $Rootfs, $Image)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "required file missing: $path" }
}
New-Item -ItemType Directory -Force -Path $ResultRoot | Out-Null
$env:GANTRY_HOME = Join-Path $ResultRoot "state"
if ($VirtioMem -eq "0") { $env:GANTRY_VIRTIO_MEM = "0" } else { $env:GANTRY_VIRTIO_MEM = "1" }

function Invoke-GantryBestEffort([string[]]$CommandArgs) {
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        & $script:Gantry @CommandArgs *> $null
        return $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $oldPreference }
}

function Measure-GantryReady([int]$MemoryMiB, [int]$Run) {
    $name = "boot-$MemoryMiB-$Run"
	$null = Invoke-GantryBestEffort @("stop", $name)
	$null = Invoke-GantryBestEffort @("delete", $name)
	$log = Join-Path $ResultRoot "$name.start.log"
	$clock = [Diagnostics.Stopwatch]::StartNew()
	& $Gantry start $name -kernel $Kernel -rootfs $Rootfs -image $Image -rw=false -mem "$MemoryMiB" -cpus "$CPUCount" -process-isolation auto *> $log
    $clock.Stop()
    if ($LASTEXITCODE -ne 0) { throw "gantry start $name failed with exit code $LASTEXITCODE" }
    $elapsed = $clock.Elapsed.TotalMilliseconds
    $null = Invoke-GantryBestEffort @("stop", $name)
    $null = Invoke-GantryBestEffort @("delete", $name)
    return $elapsed
}

function Measure-QemuMicrovmVminitd([int]$MemoryMiB, [int]$Run) {
    $serial = Join-Path $ResultRoot "qemu-microvm-$MemoryMiB-$Run.serial.log"
    Remove-Item $serial -Force -ErrorAction SilentlyContinue
	$port = 39000 + (([Math]::Floor($MemoryMiB / 128) + $Run) % 1000)
	$append = "console=ttyS0 loglevel=4 init_on_alloc=1 init_on_free=0 root=/dev/vda rootfstype=erofs ro nokaslr init=/sbin/vminitd noapic virtio_mmio.device=512@0xfeb00000:5 -- -vsock-rpc-port=1025 -vsock-stream-port=1026 -vsock-cid=3"
	$needle = '"msg":"system init completed"'
    $arguments = @(
        "-M", "microvm,kernel-irqchip=off,acpi=off",
        "-accel", "whpx",
        "-cpu", "max,-vmx",
        "-smp", "$CPUCount",
        "-m", "${MemoryMiB}M",
		"-nodefaults", "-no-user-config", "-no-reboot", "-display", "none", "-monitor", "none",
		# QEMU's Windows file chardev buffers output until close. A loopback
		# chardev exposes the milestone live without changing the guest machine.
		"-serial", "tcp:127.0.0.1:${port},server=on,wait=on",
		"-kernel", $Kernel,
		"-append", ('"{0}"' -f $append),
		"-drive", ('"if=none,id=root,format=raw,readonly=on,file={0}"' -f $Rootfs),
		"-device", "virtio-blk-device,drive=root,bus=virtio-mmio-bus.0"
    )
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $Qemu -ArgumentList $arguments -PassThru -WindowStyle Hidden
	$client = $null
	$serialText = ""
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds($QemuTimeoutSeconds)
		while ($null -eq $client -and [DateTime]::UtcNow -lt $deadline) {
			$candidate = New-Object Net.Sockets.TcpClient
			try {
				$candidate.Connect("127.0.0.1", $port)
				$client = $candidate
			}
			catch {
				$candidate.Dispose()
				if ($process.HasExited) { throw "QEMU microvm exited with code $($process.ExitCode) before opening its serial chardev" }
				Start-Sleep -Milliseconds 5
			}
		}
		if ($null -eq $client) { throw "QEMU microvm did not open its serial chardev" }
		$stream = $client.GetStream()
		$buffer = New-Object byte[] 4096
        while ([DateTime]::UtcNow -lt $deadline) {
			while ($stream.DataAvailable) {
				$count = $stream.Read($buffer, 0, $buffer.Length)
				if ($count -le 0) { break }
				$serialText += [Text.Encoding]::UTF8.GetString($buffer, 0, $count)
			}
			if ($serialText.Contains($needle)) { $clock.Stop(); return $clock.Elapsed.TotalMilliseconds }
			if ($process.HasExited) { throw "QEMU microvm exited with code $($process.ExitCode) before vminitd initialization" }
            Start-Sleep -Milliseconds 5
        }
		throw "QEMU microvm did not reach vminitd initialization within $QemuTimeoutSeconds seconds"
    }
    finally {
		if ($null -ne $client) { $client.Dispose() }
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
        $process.WaitForExit()
        $process.Dispose()
		[IO.File]::WriteAllText($serial, $serialText)
    }
}

$rows = @()
foreach ($memory in $MemoryList) {
    for ($run = 1; $run -le $Repeats; $run++) {
        $gantryMs = Measure-GantryReady $memory $run
        $rows += [pscustomobject]@{ implementation = "gantry"; machine = "native-whpx"; milestone = "daemon-ready"; memory_mib = $memory; cpus = $CPUCount; run = $run; elapsed_ms = [Math]::Round($gantryMs, 3); virtio_mem = $VirtioMem }
		$qemuMs = Measure-QemuMicrovmVminitd $memory $run
		$rows += [pscustomobject]@{ implementation = "qemu"; machine = "microvm"; milestone = "vminitd-system-init"; memory_mib = $memory; cpus = $CPUCount; run = $run; elapsed_ms = [Math]::Round($qemuMs, 3); virtio_mem = "n/a" }
		"memory=$memory run=$run gantry-ready=$([Math]::Round($gantryMs, 3))ms qemu-microvm-vminitd=$([Math]::Round($qemuMs, 3))ms"
    }
}
$rows | Export-Csv -NoTypeInformation -Path (Join-Path $ResultRoot "raw.csv")

$rows | Group-Object implementation, machine, milestone, memory_mib | ForEach-Object {
    $ordered = @($_.Group.elapsed_ms | Sort-Object)
    [pscustomobject]@{
        implementation = $_.Group[0].implementation
        machine = $_.Group[0].machine
        milestone = $_.Group[0].milestone
        memory_mib = $_.Group[0].memory_mib
        median_ms = $ordered[[Math]::Floor($ordered.Count / 2)]
    }
} | Sort-Object memory_mib, implementation | Format-Table -AutoSize
