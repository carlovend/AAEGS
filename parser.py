import os
import re
import json
import csv

### === VULHUB PARSER ===

def parse_vulhub_repo(vulhub_root):
    cve_regex = re.compile(r'CVE[-_ ]?\d{4}[-_ ]?\d+', re.IGNORECASE)
    cve_map = {}
    for root, dirs, files in os.walk(vulhub_root):
        for dirname in dirs:
            match = cve_regex.search(dirname)
            if match:
                cve = match.group(0).replace("_", "-").replace(" ", "-").upper()
                cve_dir = os.path.join(root, dirname)
                cve_map.setdefault(cve, []).append(os.path.abspath(cve_dir))
        # Include anche file (opzionale, se ne hai direttamente in Vulhub)
        for fname in files:
            match = cve_regex.search(fname)
            if match:
                cve = match.group(0).replace("_", "-").replace(" ", "-").upper()
                cve_file = os.path.join(root, fname)
                cve_map.setdefault(cve, []).append(os.path.abspath(cve_file))
    return cve_map

### === EXPLOITDB PARSER ===

def parse_exploitdb_csv(csv_path, exploits_root):
    cve_map = {}
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_field = row.get('cve') or row.get('cveid') or ""
            exploit_file = row.get('file') or row.get('path') or ""
            if cve_field and exploit_file:
                for cve in cve_field.split(','):
                    cve = cve.strip().replace("_", "-").replace(" ", "-").upper()
                    full_path = os.path.abspath(os.path.join(exploits_root, exploit_file))
                    cve_map.setdefault(cve, []).append(full_path)
    return cve_map

### === PoC-in-GitHub PARSER (FLESSIBILE: directory E file) ===

def parse_poc_in_github_repo(poc_root):
    cve_regex = re.compile(r'CVE[-_ ]?\d{4}[-_ ]?\d+', re.IGNORECASE)
    cve_map = {}
    for root, dirs, files in os.walk(poc_root):
        for dirname in dirs:
            match = cve_regex.search(dirname)
            if match:
                cve = match.group(0).replace("_", "-").replace(" ", "-").upper()
                cve_dir = os.path.join(root, dirname)
                cve_map.setdefault(cve, []).append(os.path.abspath(cve_dir))
        for fname in files:
            match = cve_regex.search(fname)
            if match:
                cve = match.group(0).replace("_", "-").replace(" ", "-").upper()
                cve_file = os.path.join(root, fname)
                cve_map.setdefault(cve, []).append(os.path.abspath(cve_file))
    return cve_map

### === LOOKUP FUNZIONE ===

class LocalPocFinder:
    def __init__(self, vulhub_map_path, exploitdb_map_path, poc_github_map_path=None):
        with open(vulhub_map_path) as f:
            self.vulhub_map = json.load(f)
        with open(exploitdb_map_path) as f:
            self.exploitdb_map = json.load(f)
        self.poc_github_map = {}
        if poc_github_map_path:
            with open(poc_github_map_path) as f:
                self.poc_github_map = json.load(f)

    def find(self, cve_id):
        cve_id = cve_id.upper()
        results = []
        for mapping in [self.vulhub_map, self.exploitdb_map, self.poc_github_map]:
            if mapping and cve_id in mapping:
                data = mapping[cve_id]
                if isinstance(data, list):
                    results.extend(data)
                else:
                    results.append(data)

        return results

### === GENERA LE MAPPE (USO UNA TANTUM) ===

if __name__ == "__main__":
    vulhub_path = input("Percorso root Vulhub: ").strip()
    exploitdb_csv = input("Percorso file files_exploits.csv: ").strip()
    exploitdb_root = input("Percorso root ExploitDB (php, python, ecc): ").strip()
    poc_github_root = input("Percorso root PoC-in-GitHub: ").strip()

    vulhub_map = parse_vulhub_repo(vulhub_path)
    with open("vulhub_cve_map.json", "w") as f:
        json.dump(vulhub_map, f, indent=2)
    print(f"[OK] Salvata la mappa Vulhub in vulhub_cve_map.json")

    exploitdb_map = parse_exploitdb_csv(exploitdb_csv, exploitdb_root)
    with open("exploitdb_cve_map.json", "w") as f:
        json.dump(exploitdb_map, f, indent=2)
    print(f"[OK] Salvata la mappa ExploitDB in exploitdb_cve_map.json")

    poc_github_map = parse_poc_in_github_repo(poc_github_root)
    with open("poc_github_cve_map.json", "w") as f:
        json.dump(poc_github_map, f, indent=2)
    print(f"[OK] Salvata la mappa PoC-in-GitHub in poc_github_cve_map.json")

    print("\nTutte le mappe sono state generate e salvate.")
