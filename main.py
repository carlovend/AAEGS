from nmap_scan import scan_target
from vuln_mapper import map_services_to_vulns
from exploit_orchestrator import generate_poc_for_service_cve
from parser import LocalPocFinder
from extract_snippets import collect_snippets_for_folder, extract_python_code_from_file, extract_code_blocks_from_readme
from ollama_utils import distill_snippets_with_ollama, extract_python_code
from remote_poc_loader import process_cve_json_and_distill_one_poc_per_repo
import os

def main():
    finder = LocalPocFinder(
        "vulhub_cve_map.json",
        "exploitdb_cve_map.json",
        "poc_github_cve_map.json"
    )

    ip = input("Inserisci l'indirizzo IP target da scansionare: ").strip()
    porta = input("Inserisci la porta da scansionare (default: 8080): ").strip() or "8080"
    print(f"\n[INFO] Avvio scansione su {ip} sulla porta {porta}\n{'=' * 40}")
    services = scan_target(ip, ports=porta)
    if not services:
        print("[!] Nessun servizio rilevato o errore durante la scansione.")
        return

    for idx, service in enumerate(services, 1):
        print(f"\n[{idx}] Servizio individuato: {service.get('product') or service.get('name')} {service.get('version', '')}")
        print(f"    IP      : {service.get('ip')}")
        print(f"    Porta   : {service.get('port')}")
        print(f"    Protocol: {service.get('protocol')}")
        print(f"    Version : {service.get('version', '-')}")

        print("[*] Ricerca vulnerabilità note...")
        vulns = map_services_to_vulns(service)
        if not vulns:
            print("    Nessuna vulnerabilità trovata.")
        else:
            print(f"    [!] Trovate {len(vulns)} vulnerabilità:")
            for v in vulns:
                print(f"        - {v['cve_id']}: {v.get('description', '')[:100]}...")
                genera = input(f"Generare un PoC Python per questa vulnerabilità ({v['cve_id']})? (y/N): ").strip().lower()
                if genera == "y":
                    lookup = finder.find(v['cve_id'])
                    print(lookup, "LOOKUP RESULT")
                    snippet_sources = []

                    for source in lookup:
                        if isinstance(source, str):
                            snippet_sources.append(source)
                        elif isinstance(source, dict):
                            snippet_sources.append(source.get('path', ''))


                    # 1. Pipeline LOCALE (Vulhub + ExploitDB + repo locali PoC-in-GitHub)
                    all_snippets = []
                    for source in snippet_sources:
                        if os.path.isdir(source):
                            all_snippets += collect_snippets_for_folder(source)
                        elif os.path.isfile(source):
                            if source.lower().endswith(".py"):
                                all_snippets.append(extract_python_code_from_file(source))
                            elif source.lower().endswith(".txt") or source.lower().startswith("readme"):
                                all_snippets += extract_code_blocks_from_readme(source)
                    if all_snippets:
                        print(f"    [+] Snippet locali trovati, distillo il context via LLM...")

                        context = distill_snippets_with_ollama(all_snippets, v['cve_id'])
                        print(context, "CONTEXT DISTILLATO")
                        print("\n--- CONTEXT DISTILLATO (usato come prompt PoC) ---\n")
                        print(context[:1500] + ("\n...[troncato]..." if len(context) > 1500 else ""))
                        poc = generate_poc_for_service_cve(service, v, context=context)
                        clean_poc = extract_python_code(poc)
                        print("\n--- PoC Python generato da context locale ---\n")
                        print(clean_poc)
                        save = input("Salvare il PoC su file? (y/N): ").strip().lower()
                        if save == "y":
                            product = (service.get('product') or service.get('name') or "service").replace(" ", "_")
                            fname = f"{product}_{v['cve_id']}_poc.py"
                            with open(fname, "w") as f:
                                f.write(clean_poc)
                            print(f"PoC salvato come {fname}")

                    # 2. Pipeline REMOTA (repo GitHub da JSON)
                    for source in snippet_sources:
                        if os.path.isfile(source) and source.lower().endswith(".json"):
                            repo_contexts = process_cve_json_and_distill_one_poc_per_repo(
                                json_path=source,
                                cve_id=v['cve_id'],
                                extract_snippets_fn=collect_snippets_for_folder,
                                ollama_distill_fn=distill_snippets_with_ollama,
                                max_repos=5,
                                repo_folder="repo"
                            )
                            print(repo_contexts)
                            # Per ogni repo remota trovata, genera un PoC separato
                            for repo_path, repo_context in repo_contexts:
                                print(f"\n[REPO REMOTA: {repo_path}]")
                                poc = generate_poc_for_service_cve(service, v, context=repo_context)
                                clean_poc = extract_python_code(poc)
                                print(f"\n--- PoC Python generato da {repo_path} ---\n")
                                print(clean_poc)
                                save = input("Salvare il PoC su file? (y/N): ").strip().lower()
                                if save == "y":
                                    product = (service.get('product') or service.get('name') or "service").replace(" ", "_")
                                    fname = f"{product}_{v['cve_id']}_{os.path.basename(repo_path)}_poc.py"
                                    with open(fname, "w") as f:
                                        f.write(clean_poc)
                                    print(f"PoC salvato come {fname}")

    print("\n[INFO] Analisi completata.")

if __name__ == "__main__":
    main()
