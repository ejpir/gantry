$ErrorActionPreference = "Stop"

function Value-OrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

$Root = Value-OrDefault "GANTRY_TEST_ROOT" "C:\gantry"
$Gantry = Value-OrDefault "GANTRY_TEST_EXE" (Join-Path $Root "gantry-field.exe")
$GuestTools = Value-OrDefault "GANTRY_TEST_GUEST" (Join-Path $Root "gantry-guest-x86_64")
$StateRoot = Value-OrDefault "GANTRY_HOME" (Join-Path $Root "state-security")
$Kernel = Value-OrDefault "GANTRY_TEST_KERNEL" (Join-Path $Root "gantry-kernel-x86_64-tinyvm6c")
$Rootfs = Value-OrDefault "GANTRY_TEST_ROOTFS" (Join-Path $Root "nerdbox-rootfs-x86_64-noinline-plain-4k.erofs")
$Image = Value-OrDefault "GANTRY_TEST_IMAGE" (Join-Path $Root "debian-netprobe-nn-ca2-4k.erofs")
$SecretsSandbox = "security-secrets"
$OAuthSandbox = "security-oauth"
$OAuthBadSandbox = "security-oauth-bad"
$MCPSandbox = "security-mcp"
$TestRoot = Join-Path $Root "security-replay"

$env:GANTRY_HOME = $StateRoot
$env:GANTRY_ARTIFACTS = $Root

function Invoke-GantryCapture([string[]]$CommandArgs) {
    $oldPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5 wraps native stderr as ErrorRecord objects.
        # Keep it capturable and use the process exit code as the authority.
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

function Invoke-GantryExpectedFailure([string[]]$CommandArgs) {
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $script:Gantry @CommandArgs 2>&1)
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
    $text = ($output | ForEach-Object { "$_" }) -join "`n"
    if ($code -eq 0) {
        throw "gantry $($CommandArgs -join ' ') unexpectedly succeeded: $text"
    }
    return $text
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

function Assert-Contains([string]$Label, [string]$Text, [string]$Needle) {
    if (-not $Text.Contains($Needle)) {
        throw "$Label`: output does not contain '$Needle': $Text"
    }
    "PASS $Label"
}

function Assert-NotContains([string]$Label, [string]$Text, [string]$Needle) {
    if ($Text.Contains($Needle)) {
        throw "$Label`: output unexpectedly contains '$Needle': $Text"
    }
    "PASS $Label"
}

function Start-TestSandbox([string]$Name, [string[]]$ExtraArgs) {
    $null = Invoke-GantryBestEffort @("stop", $Name)
    $null = Invoke-GantryBestEffort @("delete", $Name)
    $args = @(
        "start", $Name,
        "-kernel", $script:Kernel,
        "-rootfs", $script:Rootfs,
        "-image", $script:Image,
        "-mem", "256",
        "-cpus", "1",
        "-process-isolation", "auto"
    ) + $ExtraArgs
    Invoke-Gantry $args
}

function Wait-GuestHelper([string]$Name) {
    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        try {
            $null = Invoke-GantryCapture @(
                "exec", $Name, "--", "test", "-x", "/run/gantry/bin/gantry-guest"
            )
            return
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }
    throw "guest helper was not staged in $Name"
}

foreach ($path in @($Gantry, $GuestTools, $Kernel, $Rootfs, $Image)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "required file missing: $path" }
}

$mockOAuth = $null
$loginProcess = $null
try {
    foreach ($sandbox in @($SecretsSandbox, $OAuthSandbox, $OAuthBadSandbox, $MCPSandbox)) {
        $null = Invoke-GantryBestEffort @("stop", $sandbox)
        $null = Invoke-GantryBestEffort @("delete", $sandbox)
    }
    if (Test-Path $TestRoot) { Remove-Item -Recurse -Force $TestRoot }
    New-Item -ItemType Directory -Force $TestRoot | Out-Null

    "===== Windows secrets and credential broker ====="
    $ambient = "win-ambient-$([Guid]::NewGuid())"
    $fileValue = "win-file-$([Guid]::NewGuid())"
    $boundValue = "win-bound-$([Guid]::NewGuid())"
    $rotatingV1 = "win-rotate-v1-$([Guid]::NewGuid())"
    $rotatingV2 = "win-rotate-v2-$([Guid]::NewGuid())"
    $fileSource = Join-Path $TestRoot "ambient-secret.txt"
    $rotatingSource = Join-Path $TestRoot "rotating-secret.txt"
    [IO.File]::WriteAllText($fileSource, $fileValue + "`n")
    [IO.File]::WriteAllText($rotatingSource, $rotatingV1 + "`n")
    $env:WIN_CANARY = $ambient
    $env:WIN_BOUND = $boundValue

    Start-TestSandbox $SecretsSandbox @(
        "-secret", "WIN_CANARY",
        "-secret", "WIN_FROM_FILE=@$fileSource",
        "-secret", "WIN_BOUND@git.test",
        "-secret", "WIN_ROTATING@files.test=@$rotatingSource,ttl=1s"
    )
    Wait-GuestHelper $SecretsSandbox

    $output = Invoke-GantryCapture @(
        "exec", $SecretsSandbox, "--", "printenv", "WIN_CANARY", "WIN_FROM_FILE"
    )
    Assert-Contains "secrets: Windows env source reaches guest" $output $ambient
    Assert-Contains "secrets: Windows file source reaches guest" $output $fileValue
    $output = Invoke-GantryCapture @("exec", $SecretsSandbox, "--", "sh", "-c", 'printenv WIN_BOUND || echo ABSENT')
    Assert-Contains "secrets: bound value is not ambient" $output "ABSENT"

    $boundInput = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("protocol=https`nhost=git.test`n`n"))
    $rotatingInput = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("protocol=https`nhost=files.test`n`n"))
    $boundQuery = "echo $boundInput | base64 -d | /run/gantry/bin/credhelper get"
    $rotatingQuery = "echo $rotatingInput | base64 -d | /run/gantry/bin/credhelper get"
    $boundOutput = ""
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $boundOutput = Invoke-GantryCapture @("exec", $SecretsSandbox, "--", "sh", "-c", $boundQuery)
        if ($boundOutput.Contains("password=$boundValue")) { break }
        Start-Sleep -Seconds 1
    }
    Assert-Contains "broker: Windows host delivers bound credential" $boundOutput "password=$boundValue"
    $rotatingOutput = ""
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $rotatingOutput = Invoke-GantryCapture @("exec", $SecretsSandbox, "--", "sh", "-c", $rotatingQuery)
        if ($rotatingOutput.Contains("password=$rotatingV1")) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $rotatingOutput.Contains("password=$rotatingV1")) {
        $daemonPath = Join-Path (Join-Path $StateRoot $SecretsSandbox) "daemon.log"
        $daemonTail = (Get-Content -Tail 30 $daemonPath) -join "`n"
        throw "broker: Windows file-backed credential was not delivered: $rotatingOutput`n$daemonTail"
    }
    "PASS broker: Windows file-backed credential delivered"
    [IO.File]::WriteAllText($rotatingSource, $rotatingV2 + "`n")
    $rotatingOutput = ""
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        Start-Sleep -Seconds 1
        $rotatingOutput = Invoke-GantryCapture @("exec", $SecretsSandbox, "--", "sh", "-c", $rotatingQuery)
        if ($rotatingOutput.Contains("password=$rotatingV2")) { break }
    }
    Assert-Contains "broker: Windows file rotation picked up live" $rotatingOutput "password=$rotatingV2"
    Remove-Item -Force $rotatingSource
    Start-Sleep -Seconds 2
    $rotatingOutput = Invoke-GantryCapture @("exec", $SecretsSandbox, "--", "sh", "-c", $rotatingQuery)
    Assert-NotContains "broker: Windows removed source fails closed" $rotatingOutput "password="

    $secretConfig = Get-Content -Raw (Join-Path (Join-Path $StateRoot $SecretsSandbox) "sandbox.json")
    Assert-Contains "secrets: names persist in Windows config" $secretConfig "WIN_CANARY"
    foreach ($value in @($ambient, $fileValue, $boundValue, $rotatingV1, $rotatingV2)) {
        Assert-NotContains "secrets: values absent from Windows config" $secretConfig $value
    }

    "===== Windows OAuth custody ====="
    $badOutput = Invoke-GantryExpectedFailure @(
        "start", $OAuthBadSandbox,
        "-kernel", $Kernel,
        "-rootfs", $Rootfs,
        "-image", $Image,
        "-oauth-custody",
        "-oauth-bridge=false"
    )
    Assert-Contains "custody: disabled callback bridge fails closed on Windows" $badOutput "requires -oauth-bridge=true"
    if (Test-Path (Join-Path $StateRoot $OAuthBadSandbox)) {
        throw "custody: refused Windows configuration created sandbox state"
    }
    "PASS custody: refused Windows configuration leaves no state"

    $mockLog = Join-Path $TestRoot "mock-oauth-grants.log"
    $mockOAuth = Start-Job -ArgumentList $mockLog -ScriptBlock {
        param([string]$LogPath)
        $ErrorActionPreference = "Stop"
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:18999/")
        $listener.Start()
        try {
            for ($request = 0; $request -lt 8; $request++) {
                $pending = $listener.BeginGetContext($null, $null)
                if (-not $pending.AsyncWaitHandle.WaitOne(120000)) { break }
                $context = $listener.EndGetContext($pending)
                $reader = New-Object IO.StreamReader($context.Request.InputStream, $context.Request.ContentEncoding)
                $body = $reader.ReadToEnd()
                $reader.Dispose()
                Add-Content -Path $LogPath -Value $body
                if ($body.Contains("refresh_token")) {
                    $json = '{"access_token":"at-win-refreshed","refresh_token":"rt-win-1","expires_in":3600}'
                }
                else {
                    $json = '{"access_token":"at-win-1","refresh_token":"rt-win-1","expires_in":1}'
                }
                $bytes = [Text.Encoding]::UTF8.GetBytes($json)
                $context.Response.StatusCode = 200
                $context.Response.ContentType = "application/json"
                $context.Response.ContentLength64 = $bytes.Length
                $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $context.Response.Close()
            }
        }
        finally {
            $listener.Close()
        }
    }
    Start-Sleep -Seconds 2
    if ($mockOAuth.State -ne "Running") {
        throw "mock OAuth server failed to start: $($mockOAuth.State)"
    }
    $env:GANTRY_OAUTH_TOKEN_URL_CLAUDE = "http://127.0.0.1:18999/token"
    Start-TestSandbox $OAuthSandbox @("-oauth-custody", "-oauth-bridge=true")
    Wait-GuestHelper $OAuthSandbox

    $loginInput = Join-Path $TestRoot "oauth-login.in"
    $loginOutput = Join-Path $TestRoot "oauth-login.out"
    $loginError = Join-Path $TestRoot "oauth-login.err"
    [IO.File]::WriteAllText($loginInput, "/run/gantry/bin/gantry-guest oauth login claude`nexit`n")
    $authorizeURL = ""
    $loginText = ""
    for ($loginAttempt = 0; $loginAttempt -lt 3; $loginAttempt++) {
        Remove-Item -Force $loginOutput, $loginError -ErrorAction SilentlyContinue
        $loginProcess = Start-Process -FilePath $Gantry -ArgumentList @("exec", $OAuthSandbox) `
            -RedirectStandardInput $loginInput -RedirectStandardOutput $loginOutput `
            -RedirectStandardError $loginError -NoNewWindow -PassThru
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 500
            $loginText = ""
            if (Test-Path $loginOutput) { $loginText += Get-Content -Raw $loginOutput }
            if (Test-Path $loginError) { $loginText += "`n" + (Get-Content -Raw $loginError) }
            $match = [regex]::Match($loginText, 'https://claude\.ai/oauth/authorize[^\s]+')
            if ($match.Success) { $authorizeURL = $match.Value; break }
            if ($loginProcess.HasExited) { break }
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not [string]::IsNullOrWhiteSpace($authorizeURL)) { break }
        if (-not $loginProcess.HasExited) {
            Stop-Process -Id $loginProcess.Id -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
    }
    if ([string]::IsNullOrWhiteSpace($authorizeURL)) {
        throw "custody: authorize URL was not emitted after three attempts: $loginText"
    }
    $portMatch = [regex]::Match($authorizeURL, '(?i)127\.0\.0\.1%3A(?<port>\d+)%2Fcallback')
    $stateMatch = [regex]::Match($authorizeURL, '[?&]state=(?<state>[A-Za-z0-9_-]+)')
    if (-not $portMatch.Success -or -not $stateMatch.Success) {
        throw "custody: could not parse callback port/state from $authorizeURL"
    }
    $callbackURL = "http://127.0.0.1:$($portMatch.Groups['port'].Value)/callback?code=mock-code&state=$($stateMatch.Groups['state'].Value)"
    $callback = Invoke-WebRequest -UseBasicParsing -Uri $callbackURL
    Assert-Contains "custody: Windows callback consumed host-side" $callback.Content "OAuth callback received"
    if (-not $loginProcess.WaitForExit(60000)) {
        Stop-Process -Id $loginProcess.Id -Force
        throw "custody: Windows guest login did not complete"
    }
    # PowerShell 5 may not populate ExitCode after the timed overload until
    # the parameterless WaitForExit drains redirected streams and Refresh
    # updates the process object.
    $loginProcess.WaitForExit()
    $loginProcess.Refresh()
    $loginExit = $loginProcess.ExitCode
    $loginText = (Get-Content -Raw $loginOutput) + "`n" + (Get-Content -Raw $loginError)
    if ($null -ne $loginExit -and $loginExit -ne 0) {
        throw "custody: Windows guest login exited ${loginExit}: $loginText"
    }
    Assert-Contains "custody: Windows guest login completed" $loginText "tokens held on host"

    $guestAuth = Invoke-GantryCapture @("exec", $OAuthSandbox, "--", "cat", "/root/.claude/.credentials.json")
    Assert-Contains "custody: Windows guest receives access token" $guestAuth "at-win-"
    Assert-Contains "custody: Windows guest refresh token is sentinel" $guestAuth "gantry-custody-refresh-held-on-host"
    $tokenFile = Join-Path (Join-Path $StateRoot $OAuthSandbox) "oauth-tokens.json"
    $tokenText = Get-Content -Raw $tokenFile
    Assert-Contains "custody: Windows host retains refresh token" $tokenText "rt-win-1"
    $tokenACL = Get-Acl $tokenFile
    if (-not $tokenACL.AreAccessRulesProtected) {
        throw "custody: Windows token-file DACL still inherits permissions"
    }
    "PASS custody: Windows token-file DACL is protected"

    $refreshDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Seconds 1
        $guestAuth = Invoke-GantryCapture @("exec", $OAuthSandbox, "--", "cat", "/root/.claude/.credentials.json")
        if ($guestAuth.Contains("at-win-refreshed")) { break }
    } while ([DateTime]::UtcNow -lt $refreshDeadline)
    Assert-Contains "custody: refreshed token reaches Windows-hosted guest" $guestAuth "at-win-refreshed"
    Invoke-Gantry @("stop", $OAuthSandbox)
    Invoke-Gantry @("resume", $OAuthSandbox)
    Start-Sleep -Seconds 4
    $daemonLog = Get-Content -Raw (Join-Path (Join-Path $StateRoot $OAuthSandbox) "daemon.log")
    Assert-Contains "custody: Windows session restored after restart" $daemonLog "session restored and access token pushed"

    "===== Windows MCP filesystem gateway ====="
    Start-TestSandbox $MCPSandbox @(
        "-mcp",
        "-mcp-fs-root", "/work",
        "-mcp-fs-user", "65534:65534"
    )
    Wait-GuestHelper $MCPSandbox
    Invoke-Gantry @(
        "exec", $MCPSandbox, "--", "sh", "-c",
        "mkdir -p /work; echo hello-windows-mcp > /work/notes.txt; ln -sf /etc/passwd /work/evil; chmod 755 /work; chmod 644 /work/notes.txt"
    )
    $requests = @(
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"whpx-battery","version":"0"}}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fs__read_file","arguments":{"path":"/work/notes.txt"}}}',
        '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fs__read_file","arguments":{"path":"/work/evil"}}}',
        '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fs__write_file","arguments":{"path":"/work/x"}}}'
    ) -join "`n"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($requests + "`n"))
    Invoke-Gantry @("exec", $MCPSandbox, "--", "sh", "-c", "printf '%s' '$encoded' | base64 -d > /work/.gantry-mcp-requests")
    $mcpOutput = Invoke-GantryCapture @(
        "exec", $MCPSandbox, "--", "sh", "-c",
        "timeout 45 /run/gantry/bin/gantry-guest mcp-proxy < /work/.gantry-mcp-requests 2>&1"
    )
    Assert-Contains "mcp: Windows tools/list exposes fs read" $mcpOutput "fs__read_file"
    Assert-Contains "mcp: Windows filesystem read round trip" $mcpOutput "hello-windows-mcp"
    $symlinkLine = ($mcpOutput -split "`n" | Where-Object { $_.Contains('"id":4') }) -join "`n"
    Assert-Contains "mcp: Windows-hosted symlink escape is rejected" $symlinkLine '"isError":true'
    Assert-NotContains "mcp: Windows-hosted symlink escape leaks nothing" $symlinkLine "root:"
    $writeLine = ($mcpOutput -split "`n" | Where-Object { $_.Contains('"id":5') }) -join "`n"
    Assert-Contains "mcp: Windows unlisted write tool is denied" $writeLine "unknown or disallowed"
    $audit = Invoke-GantryCapture @("audit", $MCPSandbox)
    Assert-Contains "mcp: Windows calls audited host-side" $audit "mcp: call fs__read_file"
    Assert-Contains "mcp: Windows denials audited host-side" $audit 'mcp: denied call "fs__write_file"'

    $mcpStateDir = Join-Path $StateRoot $MCPSandbox
    $isolation = Get-Content -Raw (Join-Path $mcpStateDir "isolation.json")
    Assert-Contains "mcp: Windows split worker topology reported" $isolation "split-mcp"
    Assert-Contains "mcp: Windows Job confinement applied" $isolation "worker job active"
    Assert-Contains "mcp: Windows AppContainer confinement applied" $isolation "zero-capability AppContainer token active"
    Assert-Contains "mcp: Windows filesystem boundary reported" $isolation '"name": "fs-read"'
    $isolationReport = $isolation | ConvertFrom-Json
    foreach ($propertyName in @("fs-read", "fs-write", "net-dial", "exec")) {
        $property = $isolationReport.mcpConfinement.properties | Where-Object { $_.name -eq $propertyName }
        if ($null -eq $property -or $property.state -ne "enforced") {
            throw "mcp: Windows AppContainer property $propertyName was not enforced: $($property | ConvertTo-Json -Compress)"
        }
    }
    "PASS mcp: Windows AppContainer enforces fs-read/fs-write/net-dial/exec"

    $daemonPid = [int](Get-Content -Raw (Join-Path $mcpStateDir "vmm.pid"))
    $mcpProcess = Get-CimInstance Win32_Process | Where-Object {
        $_.ParentProcessId -eq $daemonPid -and $_.CommandLine -like "*_mcp-worker*"
    } | Select-Object -First 1
    if ($null -eq $mcpProcess) { throw "mcp: Windows _mcp-worker child was not found" }
    "PASS mcp: Windows _mcp-worker child process running"
    Stop-Process -Id $mcpProcess.ProcessId -Force
    Start-Sleep -Seconds 2
    $output = Invoke-GantryCapture @("exec", $MCPSandbox, "--", "echo", "VM-STILL-ALIVE")
    Assert-Contains "mcp: Windows worker death does not kill VM" $output "VM-STILL-ALIVE"
    $isolation = Get-Content -Raw (Join-Path $mcpStateDir "isolation.json")
    Assert-NotContains "mcp: Windows dead worker withdrawn from topology" $isolation "split-mcp"
    Assert-Contains "mcp: Windows dead worker degradation recorded" $isolation "mcp worker confinement report unavailable"

    Invoke-Gantry @("stop", $MCPSandbox)
    $daemonLog = Get-Content -Raw (Join-Path $mcpStateDir "daemon.log")
    Assert-NotContains "shares: Windows shutdown handles FUSE SYNCFS" $daemonLog "Unimplemented opcode SYNCFS"

    "RESULT: Windows WHPX secrets/OAuth/MCP validation passed"
}
finally {
    if ($null -ne $loginProcess -and -not $loginProcess.HasExited) {
        Stop-Process -Id $loginProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $mockOAuth) {
        Stop-Job $mockOAuth -ErrorAction SilentlyContinue
        Remove-Job $mockOAuth -Force -ErrorAction SilentlyContinue
    }
    foreach ($sandbox in @($SecretsSandbox, $OAuthSandbox, $OAuthBadSandbox, $MCPSandbox)) {
        $null = Invoke-GantryBestEffort @("stop", $sandbox)
        $null = Invoke-GantryBestEffort @("delete", $sandbox)
    }
    Remove-Item Env:WIN_CANARY -ErrorAction SilentlyContinue
    Remove-Item Env:WIN_BOUND -ErrorAction SilentlyContinue
    Remove-Item Env:GANTRY_OAUTH_TOKEN_URL_CLAUDE -ErrorAction SilentlyContinue
    if (Test-Path $TestRoot) { Remove-Item -Recurse -Force $TestRoot }
}
