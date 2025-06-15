import os
import re

def parse_poc_in_github_repo(poc_root):
    """
    Scansiona ricorsivamente PoC-in-GitHub e mappa ogni CVE a tutti i path (file o cartelle) trovati.
    Restituisce {CVE: [percorsi_assoluti]}.
    """
    cve_regex = re.compile(r'CVE[-_ ]?\d{4}[-_ ]?\d+', re.IGNORECASE)
    cve_map = {}
    for root, dirs, files in os.walk(poc_root):
        # Directory
        for dirname in dirs:
            match = cve_regex.search(dirname)
            if match:
                cve = match.group(0).replace("_", "-").replace(" ", "-").upper()
                cve_dir = os.path.join(root, dirname)
                cve_map.setdefault(cve, []).append(os.path.abspath(cve_dir))
        # File
        for fname in files:
            match = cve_regex.search(fname)
            if match:
                cve = match.group(0).replace("_", "-").replace(" ", "-").upper()
                cve_file = os.path.join(root, fname)
                cve_map.setdefault(cve, []).append(os.path.abspath(cve_file))
    return cve_map

# Esempio d'uso:
if __name__ == "__main__":
    poc_github_root = os.getenv("POC_IN_GITHUB")
    poc_github_map = parse_poc_in_github_repo(poc_github_root)
    print(f"Trovate {len(poc_github_map)} CVE nella repo PoC-in-GitHub.")
    import json
    with open("poc_github_cve_map.json", "w") as f:
        json.dump(poc_github_map, f, indent=2)
