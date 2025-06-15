import os
import re

def extract_python_code_from_file(filepath):
    """Estrae tutto il codice python da un file .py."""
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            code = f.read()
        return code
    except Exception as e:
        print(f"[WARN] Impossibile leggere {filepath}: {e}")
        return ""

def extract_code_blocks_from_readme(readme_path):
    """
    Estrae blocchi di codice e comandi dai README.
    - Blocchi tra ``` o ```python o ```bash
    - Righe che iniziano con '$', 'python ', 'pip ', ecc.
    """
    code_blocks = []
    try:
        with open(readme_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # Estrai blocchi tra ```
        triple_backtick_blocks = re.findall(r"```(?:python|bash|shell)?\n(.*?)```", content, re.DOTALL)
        code_blocks.extend([block.strip() for block in triple_backtick_blocks if block.strip()])
        # Estrai righe singole tipo shell/comando
        line_blocks = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("$") or \
               line.startswith("python ") or \
               line.startswith("pip ") or \
               line.startswith("curl ") or \
               line.startswith("wget "):
                line_blocks.append(line)
        if line_blocks:
            code_blocks.append("\n".join(line_blocks))
    except Exception as e:
        print(f"[WARN] Impossibile leggere {readme_path}: {e}")
    return code_blocks

def collect_snippets_for_folder(folder_path):
    """
    Per una cartella CVE/Exploit, estrae tutti i codici python e comandi dai readme.
    Restituisce una lista di stringhe con i blocchi estratti.
    """
    snippets = []
    # Estrai da README
    for fname in os.listdir(folder_path):
        if fname.lower().startswith("readme"):
            snippets += extract_code_blocks_from_readme(os.path.join(folder_path, fname))
    # Estrai da file .py
    for fname in os.listdir(folder_path):
        if fname.lower().endswith(".py"):
            py_code = extract_python_code_from_file(os.path.join(folder_path, fname))
            if py_code:
                snippets.append(py_code)
    return snippets

