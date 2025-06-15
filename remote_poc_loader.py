import json
import os
import subprocess

def filter_github_poc_repos(repo_list, min_stars=1, min_forks=1):
    """
    Restituisce una lista filtrata di repo PoC GitHub.
    """
    valid = []
    blacklist_words = ["test", "mirror", "collection", "awesome", "scan", "checker"]
    for repo in repo_list:
        name = repo.get("name", "").lower()
        description = repo.get("description") or ""
        stars = int(repo.get("stargazers_count", 0))
        forks = int(repo.get("forks_count", 0))
        if (
            (stars >= min_stars or forks >= min_forks) and
            description and
            not any(word in name for word in blacklist_words)
        ):
            valid.append(repo)
    return valid

def clone_github_repo(repo_url, base_folder="repo"):
    """
    Clona una repo GitHub in una cartella base persistente.
    """
    if not os.path.exists(base_folder):
        os.makedirs(base_folder)
    repo_name = repo_url.rstrip('/').split('/')[-1]
    dest_path = os.path.join(base_folder, repo_name)
    if os.path.exists(dest_path):
        print(f"[!] Repo già clonata: {dest_path}")
        return dest_path
    try:
        subprocess.run(['git', 'clone', '--depth', '1', repo_url, dest_path], check=True, capture_output=True)
        print(f"[OK] Clonata {repo_url} in {dest_path}")
        return dest_path
    except Exception as e:
        print(f"[ERROR] Clonazione fallita: {repo_url} — {e}")
        return None

def process_cve_json_and_distill_one_poc_per_repo(
    json_path, cve_id, extract_snippets_fn, ollama_distill_fn, max_repos=5, repo_folder= os.getenv("REPO")
):
    """
    Per ogni repo valida (max N), clona, estrae snippet e distilla un context separato.
    Ritorna lista di tuple (repo_path, context).
    """
    with open(json_path, "r") as f:
        try:
            repo_list = json.load(f)
        except Exception as e:
            print(f"[ERROR] JSON parse error in {json_path}: {e}")
            return []

    #repo_list = filter_github_poc_repos(repo_list)[:max_repos]
    results = []

    for repo in repo_list:
        url = repo.get("html_url")
        if not url:
            continue
        print(f"[INFO] Clono repo: {url}")
        repo_path = clone_github_repo(url, repo_folder)
        if repo_path:
            snippets = extract_snippets_fn(repo_path)
            if snippets:
                context = ollama_distill_fn(snippets, cve_id)
                print("\n=== CONTEXT DISTILLATO (da repo: {}) ===\n".format(url))
                print(context[:1500] + ("\n...[troncato]..." if len(context) > 1500 else ""))
                results.append((repo_path, context))
            else:
                print(f"[*] Nessuno snippet rilevato nella repo: {url}")
        else:
            print(f"[!] Repo non clonata: {url}")

    return results
