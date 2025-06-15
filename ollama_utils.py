import requests
import re
# ========== CONFIGURATION ==========
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "deepseek-coder-v2:16b"


# ========== OLLAMA API UTILS ==========

def run_ollama(prompt: str, model: str = OLLAMA_MODEL) -> str:
    """
    Sends a prompt to the Ollama HTTP API and returns the generated response as a string.
    """
    response = requests.post(
        OLLAMA_API_URL,
        json={
            "model": model,
            "prompt": prompt,
            "stream": False
        },
        timeout=180
    )
    if not response.ok:
        print(f"[ollama][error] HTTP {response.status_code}: {response.text}")
        return ""
    data = response.json()
    return data.get("response", "")

# ========== PROMPT GENERATION UTILS ==========


def build_poc_prompt(service, cve, context=""):
    context_block = f"\nContext Snippets:\n{context}" if context else ""
    return f"""You are an expert in exploit development.
Below is the context for a vulnerability found on a real-world service.

Target:
- IP address: {service.get('ip')}
- Port: {service.get('port')}
- Product: {service.get('product')}
- Version: {service.get('version')}
{context_block}

Vulnerability:
- CVE: {cve.get('cve_id', 'N/A')}
- Description: {cve.get('description', 'N/A')}
- CVSS: {cve.get('cvss', 'N/A')}
- CWE: {cve.get('cwe', 'N/A')}
- Link: {cve.get('url', 'N/A')}

Request:
Only output a minimal, fully working Python proof-of-concept exploit for this vulnerability, using the commands and code provided above if helpful.
Do not add any explanations, comments, or extra text. Output only the code.
When possible do not use requestes, use http.client.
Avoid using http.client or urllib if the exploit relies on raw, non-normalized paths (e.g., %u002e, double-encoding). These libraries may decode or normalize the URL automatically, breaking the exploit.
Use a raw socket-based approach in such cases to preserve the exact payload.
"""


def build_distillation_prompt(snippets, cve_id):
    """
    Crea un prompt per l'LLM che chiede di estrarre SOLO comandi e codice python utili dai blocchi forniti.
    """
    blocks = "\n\n".join(f"Block {i+1}:\n{snip}" for i, snip in enumerate(snippets))
    prompt = f"""
You are an expert exploit developer and analyst.

Below are one or more code and command blocks taken from real Proof-of-Concepts (PoCs) or readme files for CVE {cve_id}.

**Task:**
Extract ONLY:
- The essential bash/shell commands to reproduce or run the PoC (install, run, exploit, etc.)
- All actually useful Python code needed to execute or reproduce the exploit


**Rules:**
- Vulnerability is always on 127.0.0.1 when you find other ip address chang it with localhost
- Do NOT include explanations, descriptive text, or example outputs.
- When possible do not use requestes, use http.client
-Avoid using http.client or urllib if the exploit relies on raw, non-normalized paths (e.g., %u002e, double-encoding). These libraries may decode or normalize the URL automatically, breaking the exploit.
  Use a raw socket-based approach in such cases to preserve the exact payload.
- Do NOT include unnecessary comments or setup instructions not relevant to exploitation.
- Output a sequence of bash/shell commands, followed by any necessary Python code, and nothing else.

**Input blocks:**
{blocks}
"""
    return prompt

def distill_snippets_with_ollama(snippets, cve_id, model=OLLAMA_MODEL):
    print(snippets, "SNIPPETS TO DISTILL")
    prompt = build_distillation_prompt(snippets, cve_id)
    response = requests.post(
        OLLAMA_API_URL,
        json={
            "model": model,
            "prompt": prompt,
            "stream": False
        },
        timeout=180
    )
    if not response.ok:
        print(f"[ollama][error] HTTP {response.status_code}: {response.text}")
        return ""
    data = response.json()
    return data.get("response", "")



def extract_python_code(llm_output: str) -> str:
    """
    Extracts only the Python code block from LLM output (even if wrapped in markdown or with explanations).
    Returns the code as a string.
    """
    # Cerca blocco ```python ... ```
    matches = re.findall(r"```python(.*?)```", llm_output, re.DOTALL | re.IGNORECASE)
    if matches:
        return matches[0].strip()
    # Se non trova python, cerca blocchi generici ```
    matches = re.findall(r"```(.*?)```", llm_output, re.DOTALL)
    if matches:
        return matches[0].strip()
    # Se non trova markdown, rimuovi eventuali spiegazioni prima della prima import
    code_start = llm_output.find("import ")
    if code_start != -1:
        return llm_output[code_start:].strip()
    # Come fallback restituisci tutto (caso raro)
    return llm_output.strip()

