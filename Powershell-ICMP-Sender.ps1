<#
    Powershell-ICMP-Sender.ps1
    ICMP sender utility for lab dashboarding

    Origin / Credit:
      - Original concept and code: Oddvar Moe (@oddvarmoe), repository "Powershell-ICMP"
      - License: BSD 3-Clause (see original)
      - Metasploit reference: https://www.rapid7.com/db/modules/auxiliary/server/icmp_exfil
      - Inspiration: https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1

    Fork / Adaptation:
      - Fork: kaestnja/Powershell-ICMP — adapted sender for simple dashboard file transfer over ICMP
      - Maintainer: Jan Kästner (kaestnja)
      - Contributions: ChatGPT ("Kati"): refactors, diagnostics, robustness

    Purpose of this fork:
      - Create and update a local "Dashboard" info file on each lab host
      - Send the file contents to the ICMP listener via crafted Echo Requests
      - Use chunked transfers if the file exceeds MTU payload size
      - Optionally wait for ACK replies (ICMP Echo Reply with transferId)

    Notes:
      - Custom protocol header: MAGIC, version, transferId, seq/total, flags, filename length + checksum + data
      - Admin privileges required to open raw sockets
      - ACKs are optional but improve reliability in controlled setups
      - Intended for lab testing and dashboard automation only

    TODO:
      - Retransmit if no ACK is received (basic reliability loop)
      - Adjustable inter-chunk delay for rate control
      - Optional encryption/authentication before sending
      - Improve error handling for large/broken transfers

    Future Ideas:
      - Multi-file batch sending in a single session
      - Support for payload compression (gzip/deflate)
      - Dynamic negotiation of MTU size with listener
#>


[CmdletBinding()]
param(
    [string]$TargetIP,
    [int]$AckWaitMs,
    [int]$ChunkDelayMs
)

$ScriptVersion = '2.3.1'

function Test-IsElevated {
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) { return [System.Environment]::IsPrivilegedProcess }
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function New-RandomUint32 {
    $hi = Get-Random -Minimum 0 -Maximum 65536
    $lo = Get-Random -Minimum 0 -Maximum 65536
    $val = ([long]$hi -shl 16) -bor [long]$lo
    return [uint32]$val
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

# Defaults und Konfig
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfgPath = Join-Path $ScriptDir 'Powershell-ICMP.config.psd1'

$DashboardFolderName = 'Dashboard'
$SharedSecret        = ''
$IcmpMtuPayload      = 1472
$UseAckIfElevated    = $true
$AckWaitMs           = if ($PSBoundParameters.ContainsKey('AckWaitMs')) { [int]$AckWaitMs } else { 5000 }
$ChunkDelayMs        = if ($PSBoundParameters.ContainsKey('ChunkDelayMs')) { [int]$ChunkDelayMs } else { 15 }
$TargetIP            = if ($PSBoundParameters.ContainsKey('TargetIP')) { $TargetIP } else { $null }

if (Test-Path -LiteralPath $cfgPath) {
    $cfg = Import-PowerShellDataFile -Path $cfgPath
    if ($cfg.DashboardFolderName) { $DashboardFolderName = $cfg.DashboardFolderName }
    if (-not $TargetIP) {
        if ($cfg.TargetIP)      { $TargetIP = $cfg.TargetIP }
        elseif ($cfg.ListenIP)  { $TargetIP = $cfg.ListenIP }
    }
    if ($cfg.AckWaitMs)           { $AckWaitMs        = [int]$cfg.AckWaitMs }
    if ($cfg.InterChunkDelayMs)   { $ChunkDelayMs     = [int]$cfg.InterChunkDelayMs }
    if ($cfg.IcmpMtuPayload)      { $IcmpMtuPayload   = [int]$cfg.IcmpMtuPayload }
    if ($cfg.UseAckIfElevated -is [bool]) { $UseAckIfElevated = $cfg.UseAckIfElevated }
    if ($cfg.SharedSecret)        { $SharedSecret = $cfg.SharedSecret }
    if ($cfg.AckWaitTimeoutMs -and -not $PSBoundParameters.ContainsKey('AckWaitMs')) { $AckWaitMs = [int]$cfg.AckWaitTimeoutMs }
}

if (-not $TargetIP) { $TargetIP = '192.168.6.50' }

# Defaults
$ProtoMagic     = [byte[]](0x49,0x43)  # 'IC'
$ProtoVersion   = 0x02
$ProtoAckMarker = 0x80
$AckReceiveMode = 'auto'

# Aus PSD1 übernehmen (falls vorhanden)
if ($cfg -and $cfg.PSObject.Properties.Name -contains 'Protocol' -and $cfg.Protocol) {
    if ($cfg.Protocol.Magic)      { $ProtoMagic     = [byte[]]$cfg.Protocol.Magic }
    if ($cfg.Protocol.Version)    { $ProtoVersion   = [int]$cfg.Protocol.Version }
    if ($cfg.Protocol.AckMarker)  { $ProtoAckMarker = [int]$cfg.Protocol.AckMarker }
    if ($cfg.Protocol.AckReceiveMode) { $AckReceiveMode = [string]$cfg.Protocol.AckReceiveMode }
}


# Banner
$IsElevated = Test-IsElevated
Write-Host "Powershell-ICMP-Sender v$ScriptVersion"
Write-Host ("Sender host: {0} | PS: {1} | Elevated: {2}" -f $env:COMPUTERNAME, $PSVersionTable.PSVersion, $IsElevated)
Write-Host ("Local IPv4: {0}" -f ((Get-LocalIPv4) -join ', '))
Write-Host ("Target IP: {0}" -f $TargetIP)

# Dashboard-Datei schreiben
$dashboardDir = Join-Path $ScriptDir $DashboardFolderName
if (-not (Test-Path -LiteralPath $dashboardDir)) { New-Item -ItemType Directory -Path $dashboardDir -Force | Out-Null }
Write-Host ("Dashboard folder exists: {0}" -f $dashboardDir)

$infoFile = Join-Path $dashboardDir ("{0}.txt" -f $env:COMPUTERNAME)
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"
@(
 "Host: $env:COMPUTERNAME"
 "PS: $($PSVersionTable.PSVersion)"
 "Elevated: $IsElevated"
 "Timestamp: $timestamp"
) | Set-Content -LiteralPath $infoFile -Encoding UTF8
Write-Host ("Info file created/updated: {0}" -f $infoFile)

# Ping
try {
    $reply = (New-Object System.Net.NetworkInformation.Ping).Send($TargetIP, 1000)
    if ($reply.Status -ne 'Success') { throw "Ping status: $($reply.Status)" }
    Write-Host ("Reachability check: success to {0}, rtt={1}ms" -f $TargetIP, $reply.RoundtripTime)
} catch { Write-Warning ("Reachability check failed: {0}" -f $_.Exception.Message) }

# Payload vorbereiten
$fileName = Split-Path -Leaf $infoFile
$fileNameBytes = [System.Text.Encoding]::UTF8.GetBytes($fileName)
$fileBytes = [System.IO.File]::ReadAllBytes($infoFile)
$sha = [System.Security.Cryptography.SHA256]::Create()
$checksum = $sha.ComputeHash($fileBytes)
$sha.Dispose()

$transferId = New-RandomUint32

# First-Chunk-App-Payload bauen
# Header: 'IC',0x02,flags(First=1),TransferId(LE),Total(LE),NameLen,ChkLen,HmacLen(0)
$icmpHeaderLen = 8
$maxAppPayload = $IcmpMtuPayload - $icmpHeaderLen
$firstHdr = New-Object byte[] 13
#$firstHdr[0]=0x49;$firstHdr[1]=0x43;$firstHdr[2]=0x02
$firstHdr[0] = $ProtoMagic[0]
$firstHdr[1] = $ProtoMagic[1]
$firstHdr[2] = [byte]$ProtoVersion
$firstHdr[3] = 0x01
$firstHdr[4]=[byte]($transferId -band 0xFF)
$firstHdr[5]=[byte](($transferId -shr 8) -band 0xFF)
$firstHdr[6]=[byte](($transferId -shr 16) -band 0xFF)
$firstHdr[7]=[byte](($transferId -shr 24) -band 0xFF)
# TotalChunks zunächst 1, wird ggf. später angepasst
$firstHdr[8]=1; $firstHdr[9]=0
$firstHdr[10]=[byte]$fileNameBytes.Length
$firstHdr[11]=[byte]$checksum.Length
$firstHdr[12]=0

# Content-Tail = name + checksum + data
$contentTail = New-Object byte[] ($fileNameBytes.Length + $checksum.Length + $fileBytes.Length)
[Array]::Copy($fileNameBytes,0,$contentTail,0,$fileNameBytes.Length)
[Array]::Copy($checksum,0,$contentTail,$fileNameBytes.Length,$checksum.Length)
[Array]::Copy($fileBytes,0,$contentTail,$fileNameBytes.Length+$checksum.Length,$fileBytes.Length)

# Slices bestimmen
$spaceForFirstSlice = $maxAppPayload - $firstHdr.Length
if ($spaceForFirstSlice -lt 1) { throw "IcmpMtuPayload too small" }

if ($contentTail.Length -le $spaceForFirstSlice) {
    $totalChunks = 1
    $firstPayload = New-Object byte[] ($firstHdr.Length + $contentTail.Length)
    [Array]::Copy($firstHdr,0,$firstPayload,0,$firstHdr.Length)
    [Array]::Copy($contentTail,0,$firstPayload,$firstHdr.Length,$contentTail.Length)
} else {
    $chunkPayloadMax = $maxAppPayload - (3 + 4 + 2 + 2)  # 'IC',ver + transferId + seq + total
    if ($chunkPayloadMax -lt 1) { throw "chunkPayloadMax too small" }
    $slices = New-Object System.Collections.Generic.List[byte[]]
    $offset = 0
    # first slice
    $take = [Math]::Min($spaceForFirstSlice, $contentTail.Length)
    $slice0 = New-Object byte[] $take
    [Array]::Copy($contentTail,0,$slice0,0,$take)
    $offset += $take
    $slices.Add($slice0)
    # continuation slices
    while ($offset -lt $contentTail.Length) {
        $take = [Math]::Min($chunkPayloadMax, $contentTail.Length - $offset)
        $s = New-Object byte[] $take
        [Array]::Copy($contentTail,$offset,$s,0,$take)
        $offset += $take
        $slices.Add($s)
    }
    $totalChunks = $slices.Count
    # TotalChunks in first header LE setzen
    $firstHdr[8]=[byte]($totalChunks -band 0xFF)
    $firstHdr[9]=[byte](($totalChunks -shr 8) -band 0xFF)
    $firstPayload = New-Object byte[] ($firstHdr.Length + $slices[0].Length)
    [Array]::Copy($firstHdr,0,$firstPayload,0,$firstHdr.Length)
    [Array]::Copy($slices[0],0,$firstPayload,$firstHdr.Length,$slices[0].Length)
}

Write-Host ("Transfer plan: ID={0} | file='{1}' | size={2} bytes | chunks={3} | chunkPayload={4} bytes" -f $transferId, $fileName, $fileBytes.Length, $totalChunks, $maxAppPayload)

# ICMP Socket
$dstIp = [System.Net.IPAddress]::Parse($TargetIP)
$dstEP = [System.Net.IPEndPoint]::new($dstIp,0)
$icmp  = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Icmp)
$icmp.SendTimeout = 3000
$icmp.ReceiveTimeout = 2000
try { $icmp.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)) } catch {}

function BuildIcmpEchoReq([byte[]]$app, [uint16]$icmpId, [uint16]$icmpSeq){
    $hdr = New-Object byte[] 8
    $hdr[0]=8; $hdr[1]=0; $hdr[2]=0; $hdr[3]=0
    $hdr[4]=[byte]($icmpId -shr 8); $hdr[5]=[byte]($icmpId -band 0xFF)
    $hdr[6]=[byte]($icmpSeq -shr 8); $hdr[7]=[byte]($icmpSeq -band 0xFF)
    $pkt = New-Object byte[] ($hdr.Length + $app.Length)
    [Array]::Copy($hdr,0,$pkt,0,$hdr.Length)
    [Array]::Copy($app,0,$pkt,$hdr.Length,$app.Length)
    # checksum
    $sum=0
    for($i=0;$i -lt $pkt.Length;$i+=2){
        $hi=[int]$pkt[$i]; $lo= if($i+1 -lt $pkt.Length){[int]$pkt[$i+1]}else{0}
        $sum += ($hi -shl 8) -bor $lo
        while($sum -gt 0xFFFF){ $sum = ($sum -band 0xFFFF) + ($sum -shr 16) }
    }
    $cs=[uint16](-bnot [uint16]$sum -band 0xFFFF)
    $pkt[2]=[byte]($cs -shr 8); $pkt[3]=[byte]($cs -band 0xFF)
    return $pkt
}

# First senden
$id16 = [uint16]($transferId -band 0xFFFF)
$seq  = [uint16]1
$pkt  = BuildIcmpEchoReq -app $firstPayload -icmpId $id16 -icmpSeq $seq
$null = $icmp.SendTo($pkt,0,$pkt.Length,[System.Net.Sockets.SocketFlags]::None,$dstEP)
Write-Host ("Sent chunk 1/{0}" -f $totalChunks)

# Continuations (falls vorhanden)
if ($totalChunks -gt 1) {
    for ($i=2; $i -le $totalChunks; $i++) {
        if ($ChunkDelayMs -gt 0) { Start-Sleep -Milliseconds $ChunkDelayMs }
        # continuation app payload
        $hdr = New-Object byte[] 11
        #$hdr[0]=0x49; $hdr[1]=0x43; $hdr[2]=0x02
        $hdr[0] = $ProtoMagic[0]
        $hdr[1] = $ProtoMagic[1]
        $hdr[2] = [byte]$ProtoVersion
        $hdr[3]=[byte]($transferId -band 0xFF)
        $hdr[4]=[byte](($transferId -shr 8) -band 0xFF)
        $hdr[5]=[byte](($transferId -shr 16) -band 0xFF)
        $hdr[6]=[byte](($transferId -shr 24) -band 0xFF)
        $hdr[7]=[byte](([uint16]$i) -band 0xFF)
        $hdr[8]=[byte](([uint16]$i) -shr 8)
        $hdr[9]=[byte]($totalChunks -band 0xFF)
        $hdr[10]=[byte](($totalChunks -shr 8) -band 0xFF)
        $slice = $slices[$i-1]
        $app = New-Object byte[] ($hdr.Length + $slice.Length)
        [Array]::Copy($hdr,0,$app,0,$hdr.Length)
        [Array]::Copy($slice,0,$app,$hdr.Length,$slice.Length)
        $pkt = BuildIcmpEchoReq -app $app -icmpId $id16 -icmpSeq ([uint16]$i)
        $null = $icmp.SendTo($pkt,0,$pkt.Length,[System.Net.Sockets.SocketFlags]::None,$dstEP)
        Write-Host ("Sent chunk {0}/{1}" -f $i, $totalChunks)
    }
}

# --- Robuster ACK-Receive: prüfe sowohl Offset 8 (kein IP-Header) als auch Offset 28 (IPv4 IHL=20) ---
function Test-AckAtOffset([byte[]]$buf, [int]$n, [int]$pos, [int]$typeIndex=0, [int]$codeIndex=1) {
    if ($n -le ($pos + 7)) { return $false }
    $type = $buf[$typeIndex]; $code = $buf[$codeIndex]
    if ($type -ne 0 -or $code -ne 0) { return $false } # ICMP Echo Reply
    if ($buf[$pos] -ne 0x49 -or $buf[$pos+1] -ne 0x43 -or $buf[$pos+2] -ne 0x02 -or $buf[$pos+3] -ne 0x80) { return $false }
    #$rid = [uint32]($buf[$pos+4] -bor ($buf[$pos+5] -shl 8) -bor ($buf[$pos+6] -shl 16) -bor ($buf[$pos+7] -shl 24))
    $rid = [uint32](
        ([uint32]$buf[$pos+4])               -bor
        (([uint32]$buf[$pos+5]) -shl 8)      -bor
        (([uint32]$buf[$pos+6]) -shl 16)     -bor
        (([uint32]$buf[$pos+7]) -shl 24)
    )
    if ($rid -ne $transferId) { return $false }
    return $true
}

function Find-AppPayloadStart([byte[]]$buf, [int]$n, [string]$mode) {
    # Liefert Startindex der App-Payload oder -1
    switch ($mode) {
        'icmp'    { $pos = 8;  if ($n -ge ($pos+4)) { return $pos } else { return -1 } }
        'ip+icmp' { $pos = 28; if ($n -ge ($pos+4)) { return $pos } else { return -1 } }
        default {
            # auto: suche 'IC' im Puffer (ab den üblichen Startpunkten)
            foreach ($start in @(8, 28, 0, 16, 32)) {
                for ($i = $start; $i -le [Math]::Max(0, $n-8); $i++) {
                    if ($buf[$i] -eq $ProtoMagic[0] -and $buf[$i+1] -eq $ProtoMagic[1]) {
                        return $i
                    }
                }
            }
            return -1
        }
    }
}

# ACK warten
if ($IsElevated -and $UseAckIfElevated -and $AckWaitMs -gt 0) {
    Write-Host ("Waiting up to {0} ms for ACK from {1}..." -f $AckWaitMs, $TargetIP)
    $ackBuf = New-Object byte[] 4096
    $remoteEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($AckWaitMs)
    $icmp.ReceiveTimeout = 500
    $gotAck = $false

    function Write-HexRange([byte[]]$b, [int]$ofs, [int]$len) {
        $len = [Math]::Min($len, [Math]::Max(0, $b.Length - $ofs))
        if ($len -le 0) { return }
        $slice = $b[$ofs..($ofs+$len-1)] | ForEach-Object { '{0:X2}' -f $_ }
        Write-Verbose ("HEX[{0}..{1}]: {2}" -f $ofs, ($ofs+$len-1), ($slice -join ' '))
    }

    while ([DateTime]::UtcNow -lt $deadline) {
        $remaining = [int]([DateTime]::UtcNow -lt $deadline ? ($deadline - [DateTime]::UtcNow).TotalMilliseconds : 0)
        try {
            $n = $icmp.ReceiveFrom($ackBuf,0,$ackBuf.Length,[System.Net.Sockets.SocketFlags]::None,[ref]$remoteEP)
            Write-Verbose ("ACK recv: {0} bytes from {1}, remaining ~{2} ms" -f $n, $remoteEP, $remaining)
            if ($n -lt 12) { Write-Verbose "ACK recv: too short (<12), continue"; continue }

            # Typ/Code-Heuristik: ICMP-only vs. IP+ICMP
            $likelyTypeIdx = 0; $likelyCodeIdx = 1
            if ($n -ge 22 -and $ackBuf[20] -in 0,8 -and $ackBuf[21] -in 0) { $likelyTypeIdx = 20; $likelyCodeIdx = 21 }
            $type = $ackBuf[$likelyTypeIdx]; $code = $ackBuf[$likelyCodeIdx]
            Write-Verbose ("ACK meta: type={0} code={1} typeIdx={2} codeIdx={3}" -f $type, $code, $likelyTypeIdx, $likelyCodeIdx)
            if ($type -ne 0 -or $code -ne 0) { Write-Verbose "ACK meta: not Echo Reply (type/code mismatch), continue"; continue }

            # 1) Auto-Suche nach App-Payload-Start
            $ok = $false
            $pos = Find-AppPayloadStart -buf $ackBuf -n $n -mode $AckReceiveMode
            Write-Verbose ("ACK search: mode='{0}' pos={1}" -f $AckReceiveMode, $pos)

            if ($pos -ge 0 -and $n -ge ($pos+8)) {
                Write-Verbose ("ACK check@pos {0}: exp Magic={1:X2} {2:X2} Ver={3:X2} Ack={4:X2}" -f $pos, $ProtoMagic[0], $ProtoMagic[1], ([byte]$ProtoVersion), ([byte]$ProtoAckMarker))
                Write-HexRange -b $ackBuf -ofs $pos -len 16
                if ($ackBuf[$pos] -eq $ProtoMagic[0] -and
                    $ackBuf[$pos+1] -eq $ProtoMagic[1] -and
                    $ackBuf[$pos+2] -eq [byte]$ProtoVersion -and
                    $ackBuf[$pos+3] -eq [byte]$ProtoAckMarker) {

                    #$rid = [uint32]($ackBuf[$pos+4] -bor ($ackBuf[$pos+5] -shl 8) -bor ($ackBuf[$pos+6] -shl 16) -bor ($ackBuf[$pos+7] -shl 24))
                    $rid = [uint32](
                        ([uint32]$ackBuf[$pos+4])               -bor
                        (([uint32]$ackBuf[$pos+5]) -shl 8)      -bor
                        (([uint32]$ackBuf[$pos+6]) -shl 16)     -bor
                        (([uint32]$ackBuf[$pos+7]) -shl 24)
                    )
                    Write-Verbose ("ACK id@pos {0}: recvId={1} expected={2}" -f $pos, $rid, $transferId)
                    if ($rid -eq $transferId) {
                        Write-Host "ACK received: SUCCESS"
                        $gotAck = $true
                        break
                    } else {
                        Write-Warning ("ACK mismatch: recvId={0} expected={1}" -f $rid, $transferId)
                    }
                } else {
                    Write-Verbose "ACK check: signature mismatch at found pos"
                }
            } else {
                Write-Verbose "ACK search: no valid pos from auto-scan"
            }

            # 2) Fallback: feste Offsets prüfen, wenn 1) nicht erfolgreich
            if (-not $gotAck) {
                # A) ICMP-only (app ab 8)
                $probePos = 8
                if ($n -ge ($probePos+8)) {
                    Write-Verbose ("ACK fallback@8: expect IC {0:X2}{1:X2} ver {2:X2} ack {3:X2}" -f $ProtoMagic[0], $ProtoMagic[1], ([byte]$ProtoVersion), ([byte]$ProtoAckMarker))
                    Write-HexRange -b $ackBuf -ofs $probePos -len 16
                    $ok = Test-AckAtOffset -buf $ackBuf -n $n -pos $probePos -typeIndex 0 -codeIndex 1
                }
                # B) IPv4(20) + ICMP(8) (app ab 28)
                if (-not $ok -and $n -ge 36) {
                    $probePos = 28
                    Write-Verbose ("ACK fallback@28: expect IC {0:X2}{1:X2} ver {2:X2} ack {3:X2}" -f $ProtoMagic[0], $ProtoMagic[1], ([byte]$ProtoVersion), ([byte]$ProtoAckMarker))
                    Write-HexRange -b $ackBuf -ofs $probePos -len 16
                    $ok = Test-AckAtOffset -buf $ackBuf -n $n -pos $probePos -typeIndex 20 -codeIndex 21
                }
                if ($ok) {
                    Write-Host "ACK received: SUCCESS"
                    $gotAck = $true
                    break
                } else {
                    Write-Verbose "ACK fallback: no match at fixed offsets"
                }
            }
        } catch [System.Net.Sockets.SocketException] {
            if ($_.NativeErrorCode -ne 10060) { Write-Warning ("ACK receive error: {0}" -f $_.Message) }
            else { Write-Verbose "ACK receive: timeout slice (no data this interval)" }
        } catch {
            Write-Warning ("ACK receive error: {0}" -f $_.Exception.Message)
        }
    }
    if (-not $gotAck) { Write-Warning "No ACK received within timeout." }
} else {
    Write-Host "Skipping ACK wait (not elevated or disabled)."
}



try { $icmp.Close() } catch {}
Write-Host ("Sender finished on host {0}." -f $env:COMPUTERNAME)
