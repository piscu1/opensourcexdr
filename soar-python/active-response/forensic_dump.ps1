# --- Forensic Evidence Capture Script ---
# This script is designed to be executed by Wazuh Active Response
# BEFORE a machine is fully isolated from the network.

$EvidenceDir = "C:\Forensics\Evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

$LogFile = "$EvidenceDir\CaptureLog.txt"
Add-Content -Path $LogFile -Value "--- Forensic Capture Started at $(Get-Date) ---"

try {
    # 1. Capture Active Network Connections (Critical for tracing Lateral Movement)
    Add-Content -Path $LogFile -Value "`n[+] Capturing Active Network Connections (netstat -ano)..."
    netstat -ano > "$EvidenceDir\netstat_output.txt"

    # 2. Capture Running Processes
    Add-Content -Path $LogFile -Value "`n[+] Capturing Running Processes (tasklist)..."
    tasklist /v > "$EvidenceDir\tasklist_output.txt"

    # 3. Capture DNS Cache (Shows recent domains resolved by malware)
    Add-Content -Path $LogFile -Value "`n[+] Capturing DNS Cache (ipconfig /displaydns)..."
    ipconfig /displaydns > "$EvidenceDir\dns_cache.txt"

    # 4. Capture Local Routing Table
    Add-Content -Path $LogFile -Value "`n[+] Capturing Routing Table (route print)..."
    route print > "$EvidenceDir\route_table.txt"

    # 5. Zip the evidence for Chain of Custody
    $ZipPath = "C:\Forensics\Evidence_Archive_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    Compress-Archive -Path "$EvidenceDir\*" -DestinationPath $ZipPath
    Add-Content -Path $LogFile -Value "`n[+] Evidence successfully zipped to $ZipPath"

    # (Pro Move for Thesis) Copy the zip to a secure network share or Wazuh Manager via API
    # Since the network might be cut milliseconds after this, local storage is safest fallback.

} catch {
    Add-Content -Path $LogFile -Value "`n[!] Error during forensic capture: $($_.Exception.Message)"
} finally {
    Add-Content -Path $LogFile -Value "`n--- Forensic Capture Ended at $(Get-Date) ---"
}
