"""
Türkçe: Risk skoru hesaplama - saf fonksiyon (global/db bağımlılığı yok).

main.py'den ayrıldı. Hem main.py'deki kalan endpoint'ler hem de routers/
paketindeki router'lar buradan import eder.
"""


def calculate_risk_score(scan_results: dict) -> int:
    """
    Türkçe: Tarama sonuçlarından risk skoru hesapla (0-100)
    """
    score = 0

    # Nuclei findings
    if "nuclei" in scan_results:
        nuclei_data = scan_results["nuclei"]
        # Handle different structures (direct findings list or wrapped in dict)
        findings = nuclei_data.get("findings", []) if isinstance(nuclei_data, dict) else []

        for f in findings:
            severity = f.get("info", {}).get("severity", "")
            if severity == "critical":
                score += 40
            elif severity == "high":
                score += 20
            elif severity == "medium":
                score += 10

    # Nmap ports
    if "nmap" in scan_results:
        nmap_data = scan_results["nmap"]
        # Allow for different nmap result structures
        output = str(nmap_data)  # Fallback search in string representation

        dangerous_ports = ["21/tcp", "23/tcp", "3389/tcp", "445/tcp"]
        for port in dangerous_ports:
            if port in output and "open" in output:
                score += 15

    return min(score, 100)  # Max 100
