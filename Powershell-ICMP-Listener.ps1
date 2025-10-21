<#
    Powershell-ICMP-Listener.ps1
    ICMP receiver utility for lab dashboarding

    Origin / Credit:
      - Original concept and code: Oddvar Moe (@oddvarmoe), repository "Powershell-ICMP"
      - License: BSD 3-Clause (see original)
      - Metasploit reference: https://www.rapid7.com/db/modules/auxiliary/server/icmp_exfil
      - Inspiration: https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1

    Fork / Adaptation:
      - Fork: kaestnja/Powershell-ICMP — adapted receiver for simple dashboard file intake over ICMP
      - Maintainer: Jan Kästner (kaestnja)
      - Contributions: ChatGPT ("Kati"): refactors, diagnostics, robustness

    Purpose of this fork:
      - Static listener on a lab host with a known IPv4 address (default 192.168.6.50)
      - Capture ICMP Echo Requests at IP layer (RCVALL) and reassemble chunked transfers
      - Verify integrity via SHA-256 checksum and write completed files atomically into a local "Dashboard" folder
      - Optionally send best-effort ACK replies to the sender (ICMP Echo Reply with transferId)

    Notes:
      - Custom protocol header: MAGIC, version, transferId, seq/total, flags, filename length + data
      - Elevated privileges are required to bind raw IP socket and enable RCVALL
      - Intended for controlled lab environments only, not for production networks

    TODO:
      - Retransmission support for missing/late chunks (beyond checksum verification)
      - Rate control / jitter handling for large multi-chunk transfers
      - Optional encryption (AES-GCM) / authentication (HMAC) for payloads
      - Configurable ACK behavior (delayed, batched, disabled)
      - Optional logging backend (JSON/CSV for later analysis)

    Future Ideas:
      - Support for IPv6 ICMP echo payloads
      - Integration with a central event dashboard or message queue
#>


[CmdletBinding()]
param()

$ScriptVersion = '2.3.1'

function Test-IsElevated {
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) { return [System.Environment]::IsPrivilegedProcess }
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-LocalIPv4 {
    try {
        [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
        ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
        ForEach-Object { $_.Address } |
        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
        ForEach-Object { $_.ToString() }
    } catch { @() }
}

# Konfig laden
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfgPath = Join-Path $ScriptDir 'Powershell-ICMP.config.psd1'
# Defaults
$ListenIP               = '192.168.6.50'
$DashboardFolderName    = 'Dashboard'
$EnableFirewallRule     = $true
$CompletedTtlMinutes    = 10
$MaxConcurrentTransfers = 64
$MaxBytesPerTransfer    = 10485760
$DebugVerbose           = $false
$AckEnabled             = $true
$SharedSecret           = ''

if (Test-Path -LiteralPath $cfgPath) {
    $cfg = Import-PowerShellDataFile -Path $cfgPath
    if ($cfg.ListenIP)               { $ListenIP = $cfg.ListenIP }
    if ($cfg.DashboardFolderName)    { $DashboardFolderName = $cfg.DashboardFolderName }
    if ($cfg.EnableFirewallRule -is [bool]) { $EnableFirewallRule = $cfg.EnableFirewallRule }
    if ($cfg.CompletedTtlMinutes)    { $CompletedTtlMinutes = [int]$cfg.CompletedTtlMinutes }
    if ($cfg.MaxConcurrentTransfers) { $MaxConcurrentTransfers = [int]$cfg.MaxConcurrentTransfers }
    if ($cfg.MaxBytesPerTransfer)    { $MaxBytesPerTransfer = [int]$cfg.MaxBytesPerTransfer }
    if ($cfg.DebugVerbose -is [bool]){ $DebugVerbose = $cfg.DebugVerbose }
    if ($cfg.AckEnabled -is [bool])  { $AckEnabled = $cfg.AckEnabled }
    if ($cfg.SharedSecret)           { $SharedSecret = $cfg.SharedSecret }
}

$IsElevated = Test-IsElevated
Write-Host "Powershell-ICMP-Listener v$ScriptVersion starting..."
Write-Host ("Listener host: {0} | PS: {1} | Elevated: {2}" -f $env:COMPUTERNAME, $PSVersionTable.PSVersion, $IsElevated)
Write-Host ("Local IPv4: {0}" -f ((Get-LocalIPv4) -join ', '))
Write-Host ("Listen IP (expected on this host): {0}" -f $ListenIP)

# Zielordner
$dashboardDir = Join-Path $ScriptDir $DashboardFolderName
if (-not (Test-Path -LiteralPath $dashboardDir)) { New-Item -ItemType Directory -Path $dashboardDir -Force | Out-Null }
Write-Host ("Dashboard folder exists: {0}" -f $dashboardDir)

# Firewallregel (ICMPv4 Echo Request)
if ($IsElevated -and $EnableFirewallRule) {
    try {
        $ruleName = 'Powershell-ICMP Listener (Echo Request)'
        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $rule) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol ICMPv4 -Program Any -LocalAddress $ListenIP -IcmpType 8 | Out-Null
        }
        Write-Host "Firewall rule present: $ruleName"
    } catch { Write-Warning "Firewall rule check failed: $($_.Exception.Message)" }
}

# Raw IP Socket öffnen
$ip = [System.Net.IPAddress]::Parse($ListenIP)
$socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,
                                               [System.Net.Sockets.SocketType]::Raw,
                                               [System.Net.Sockets.ProtocolType]::IP)
$socket.Bind([System.Net.IPEndPoint]::new($ip, 0))
$socket.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::HeaderIncluded, $true)
# ReceiveAll aktivieren
$in = New-Object byte[] 4
$out = New-Object byte[] 4
[Buffer]::BlockCopy([BitConverter]::GetBytes(1),0,$in,0,4)
$null = $socket.IOControl(0x98000001, $in, $out)  # SIO_RCVALL
Write-Host "IP raw socket bound to $ListenIP — RCVALL enabled. Press Ctrl+C to stop."

# Transferstatus
#$completed = [System.Collections.Concurrent.ConcurrentDictionary[string, datetime]]::new()
$completed = New-Object 'System.Collections.Concurrent.ConcurrentDictionary[System.String,System.DateTime]'
$ttl = [TimeSpan]::FromMinutes($CompletedTtlMinutes)

# Hilfen
function Parse-UInt16LE([byte[]]$b, [int]$ofs) {
    return [uint16](([uint32]$b[$ofs]) -bor (([uint32]$b[$ofs+1]) -shl 8))
}
function Parse-UInt32LE([byte[]]$b, [int]$ofs) {
    return [uint32](
        ([uint32]$b[$ofs])           -bor
        (([uint32]$b[$ofs+1]) -shl 8)  -bor
        (([uint32]$b[$ofs+2]) -shl 16) -bor
        (([uint32]$b[$ofs+3]) -shl 24)
    )
}

function Write-HexRange([byte[]]$b, [int]$ofs, [int]$len) {
    $len = [Math]::Min($len, [Math]::Max(0, $b.Length - $ofs))
    if ($len -le 0) { return }
    $slice = $b[$ofs..($ofs+$len-1)] | ForEach-Object { '{0:X2}' -f $_ }
    Write-Verbose ("HEX[{0}..{1}]: {2}" -f $ofs, ($ofs+$len-1), ($slice -join ' '))
}

function Save-Atomic([byte[]]$content, [string]$finalPath) {
    $tmp = "$finalPath.part"
    [System.IO.File]::WriteAllBytes($tmp, $content)
    if (Test-Path $finalPath) { Remove-Item -LiteralPath $finalPath -Force }
    Move-Item -LiteralPath $tmp -Destination $finalPath -Force
}

# ACK senden
function Send-Ack([System.Net.IPAddress]$dstIp, [uint32]$transferId) {
    if (-not $AckEnabled) { return }
    try {
        $icmp = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,
                                                     [System.Net.Sockets.SocketType]::Raw,
                                                     [System.Net.Sockets.ProtocolType]::Icmp)
        $dst = [System.Net.IPEndPoint]::new($dstIp, 0)
        # Echo Reply header
        $hdr = New-Object byte[] 8
        $hdr[0]=0; $hdr[1]=0  # Type=0 Code=0
        # id/seq egal -> 0
        # App-Payload: 'I','C',0x02,0x80,<transferId LE>
        $app = New-Object byte[] 8
        $app[0]=0x49; $app[1]=0x43; $app[2]=0x02; $app[3]=0x80
        $app[4]=[byte]($transferId -band 0xFF)
        $app[5]=[byte](($transferId -shr 8) -band 0xFF)
        $app[6]=[byte](($transferId -shr 16) -band 0xFF)
        $app[7]=[byte](($transferId -shr 24) -band 0xFF)
        Write-Verbose ("ACK build: id={0} (LE bytes below)" -f $transferId)
        Write-HexRange -b $app -ofs 0 -len 8
        $pkt = New-Object byte[] ($hdr.Length + $app.Length)
        [Array]::Copy($hdr,0,$pkt,0,$hdr.Length)
        [Array]::Copy($app,0,$pkt,$hdr.Length,$app.Length)
        # Checksum
        $sum=0
        for($i=0;$i -lt $pkt.Length;$i+=2){
            $hi=[int]$pkt[$i]; $lo= if($i+1 -lt $pkt.Length){[int]$pkt[$i+1]}else{0}
            $sum += ($hi -shl 8) -bor $lo
            while($sum -gt 0xFFFF){ $sum = ($sum -band 0xFFFF) + ($sum -shr 16) }
        }
        $cs=[uint16](-bnot [uint16]$sum -band 0xFFFF)
        $pkt[2]=[byte]($cs -shr 8); $pkt[3]=[byte]($cs -band 0xFF)
        $null = $icmp.SendTo($pkt,0,$pkt.Length,[System.Net.Sockets.SocketFlags]::None,$dst)
        try{ $icmp.Close() }catch{}
        Write-Host ("Send-Ack invoked -> dest={0} id={1} status=0" -f $dstIp, $transferId)
    } catch {
        Write-Warning ("Send-Ack error: {0}" -f $_.Exception.Message)
    }
}

# Loop
$buf = New-Object byte[] 65536
try {
    while ($true) {
        $n = $socket.Receive($buf)
        if ($n -lt 28) { continue } # IPv4 min header 20 + ICMP 8
        # IPv4 Header len
        $ihl = ($buf[0] -band 0x0F) * 4
        if ($ihl -lt 20) { continue }
        $proto = $buf[9]
        if ($proto -ne 1) { continue } # ICMP
        $srcIP = [System.Net.IPAddress]::new($buf[12..15])
        $dstIP = [System.Net.IPAddress]::new($buf[16..19])
        if ($dstIP.ToString() -ne $ListenIP) { continue }

        $icmpOfs = $ihl
        if ($n -lt ($icmpOfs + 8)) { continue }
        $type = $buf[$icmpOfs]; $code = $buf[$icmpOfs+1]
        if ($type -ne 8 -or $code -ne 0) { continue }  # nur Echo Request als Datenquelle

        $appOfs = $icmpOfs + 8
        if ($n -lt ($appOfs + 3)) { continue }
        if ($buf[$appOfs] -ne 0x49 -or $buf[$appOfs+1] -ne 0x43 -or $buf[$appOfs+2] -ne 0x02) { continue }
        Write-HexRange -b $buf -ofs $appOfs -len 16

        # First vs continuation?
        $flags = $buf[$appOfs+3]
        if (($flags -band 0x01) -eq 0x01) {
            # First chunk
            if ($n -lt ($appOfs + 13)) { continue }
            $pos = $appOfs + 4
            $transferId = Parse-UInt32LE $buf $pos; $pos+=4
            $totalChunks = Parse-UInt16LE $buf $pos; $pos+=2
            $nameLen = $buf[$pos]; $pos++
            $chkLen  = $buf[$pos]; $pos++
            $hmacLen = $buf[$pos]; $pos++
            #Write-Verbose ("RX first-chunk @pos={0} flags=0x{1:X2} id={2} total={3} nameLen={4}" -f $pos, $flags, $transferId, $totalChunks, $fileNameLen)
            Write-Verbose ("RX first-chunk @pos={0} flags=0x{1:X2} id={2} total={3} nameLen={4}" -f $pos, $flags, $transferId, $totalChunks, $nameLen)
            Write-HexRange -b $buf -ofs $pos -len 16
            if ($n -lt ($pos + $nameLen + $chkLen)) { continue }
            $nameBytes = $buf[$pos..($pos+$nameLen-1)]; $pos+=$nameLen
            $checksum  = $buf[$pos..($pos+$chkLen-1)]; $pos+=$chkLen
            $firstSliceLen = $n - $pos
            $firstSlice = if ($firstSliceLen -gt 0) { [byte[]]($buf[$pos..($n-1)]) } else { [byte[]]@() }

            $fileName = [System.Text.Encoding]::UTF8.GetString($nameBytes)
            Write-Host ("New transfer from {0}: ID={1}, totalChunks={2}, fileName='{3}'" -f $srcIP, $transferId, $totalChunks, $fileName)

            # State initialisieren
            $stateKey = "$($srcIP)|$transferId"
            $state = @{
                TransferId = $transferId
                FileName   = $fileName
                Checksum   = $checksum
                Total      = $totalChunks
                #Slices     = [System.Collections.Generic.Dictionary[System.Int32, System.Byte[]]]::new()
                # Falls das in deinem pwsh zickt, alternativ:
                Slices = New-Object 'System.Collections.Generic.Dictionary[System.Int32,System.Byte[]]'
                FirstSeen  = Get-Date
            }
            if ($firstSliceLen -gt 0) { $state.Slices[1] = $firstSlice }
            Set-Variable -Scope Script -Name ("t_" + ($stateKey -replace '\W','_')) -Value $state -Force

            # Fast-Path: Single-Chunk-Transfer sofort vervollständigen
            if ($totalChunks -eq 1) {
                # 1) Inhalte zusammenstellen (nur der erste Slice)
                $raw = $firstSlice

                # 2) Checksumme prüfen (SHA-256)
                $sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $calc = $sha.ComputeHash($raw)
                } finally {
                    $sha.Dispose()
                }
                $ok = ($calc.Length -eq $state.Checksum.Length)
                if ($ok) {
                    for ($i=0; $i -lt $calc.Length; $i++) {
                        if ($calc[$i] -ne $state.Checksum[$i]) { $ok = $false; break }
                    }
                }
                if (-not $ok) {
                    Write-Warning "Checksum mismatch for transfer $transferId from $srcIP (single-chunk)"
                    return
                }

                # 3) Datei speichern (atomar) mit Zeitstempel
                $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $destName = [System.IO.Path]::GetFileNameWithoutExtension($state.FileName) + "_$stamp" + [System.IO.Path]::GetExtension($state.FileName)
                $destPath = Join-Path $dashboardDir $destName
                Save-Atomic -content $raw -finalPath $destPath
                Write-Host ("Saved: {0}" -f $destPath)

                # 4) ACK senden
                Send-Ack -dstIp $srcIP -transferId $transferId

                # 5) State bereinigen
                $varName = "t_" + ($stateKey -replace '\W','_')
                Remove-Variable -Scope Script -Name $varName -ErrorAction SilentlyContinue
            }
        } else {
            # Continuation
            if ($n -lt ($appOfs + 11)) { continue }
            $pos = $appOfs + 3
            $transferId = Parse-UInt32LE $buf $pos; $pos+=4
            $seq = Parse-UInt16LE $buf $pos; $pos+=2
            $totalChunks = Parse-UInt16LE $buf $pos; $pos+=2
            $sliceLen = $n - $pos
            $slice = if ($sliceLen -gt 0) { [byte[]]($buf[$pos..($n-1)]) } else { [byte[]]@() }

            $stateKey = "$($srcIP)|$transferId"
            $varName = "t_" + ($stateKey -replace '\W','_')
            $state = Get-Variable -Scope Script -Name $varName -ErrorAction SilentlyContinue | ForEach-Object { $_.Value }
            if (-not $state) { continue } # kein first chunk gesehen
            $state.Slices[$seq] = $slice
            # fertig?
            if ($state.Slices.Count -ge $state.Total) {
                # zusammensetzen
                $content = New-Object System.IO.MemoryStream
                for ($i=1; $i -le $state.Total; $i++) {
                    if (-not $state.Slices.ContainsKey($i)) { continue 2 }
                    $bytes = $state.Slices[$i]
                    if ($bytes.Length -gt 0) { $content.Write($bytes,0,$bytes.Length) }
                }
                $raw = $content.ToArray()
                $content.Dispose()

                # Prüfsumme
                $sha = [System.Security.Cryptography.SHA256]::Create()
                $calc = $sha.ComputeHash($raw)
                $sha.Dispose()
                $ok = ($calc.Length -eq $state.Checksum.Length)
                if ($ok) {
                    for ($i=0; $i -lt $calc.Length; $i++) { if ($calc[$i] -ne $state.Checksum[$i]) { $ok = $false; break } }
                }
                if (-not $ok) {
                    Write-Warning "Checksum mismatch for transfer $transferId from $srcIP"
                    continue
                }
                # Save
                $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $destName = [System.IO.Path]::GetFileNameWithoutExtension($state.FileName) + "_$stamp" + [System.IO.Path]::GetExtension($state.FileName)
                $destPath = Join-Path $dashboardDir $destName
                Save-Atomic -content $raw -finalPath $destPath
                Write-Host ("Saved: {0}" -f $destPath)

                # ACK
                Send-Ack -dstIp $srcIP -transferId $transferId

                # Cleanup state
                Remove-Variable -Scope Script -Name $varName -ErrorAction SilentlyContinue
            }
        }
    }
} finally {
    try {
        # RCVALL aus
        $in = New-Object byte[] 4; $out = New-Object byte[] 4
        [Buffer]::BlockCopy([BitConverter]::GetBytes(0),0,$in,0,4)
        $null = $socket.IOControl(0x98000001, $in, $out)
        $socket.Close()
    } catch {}
}
