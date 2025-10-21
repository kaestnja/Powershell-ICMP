@{
    # Gemeinsame Basis
    ListenIP               = '192.168.6.50'
    DashboardFolderName    = 'Dashboard'
    SharedSecret           = 'ICMP-LAB-SECRET'   # derzeit nur für ACK-Prüfung genutzt (optional)

    # Listener
    EnableFirewallRule     = $true
    CompletedTtlMinutes    = 10
    MaxConcurrentTransfers = 64
    MaxBytesPerTransfer    = 10485760  # 10 MB
    DebugVerbose           = $false
    AckEnabled             = $true

    # Sender
    # TargetIP absichtlich NICHT gesetzt -> Sender verwendet ListenIP
    InterChunkDelayMs      = 15
    AckWaitTimeoutMs       = 5000
    IcmpMtuPayload         = 1472
    UseAckIfElevated       = $true

    Protocol = @{
        Magic         = @([byte]0x49, [byte]0x43)  # 'I','C'
        Version       = 0x02
        AckMarker     = 0x80
        # optional: Empfangsstrategie beim Sender (ACK):
        # "auto" = suche 'IC' im ICMP-Payload (robust), "icmp" = erwarte Payload ab Offset 8, "ip+icmp" = ab Offset 28
        AckReceiveMode = 'auto'
    }

    Transfer = @{
        ChunkSize    = 1024
        MaxRetries   = 5
        RetryDelayMs = 200
        EndMarker    = @([byte]0x45, [byte]0x4E, [byte]0x44)  # 'E','N','D'
    }
}
