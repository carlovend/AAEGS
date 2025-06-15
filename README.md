# 🛠️ Automatic PoC Generator (Work in Progress)

Questo progetto mira a generare automaticamente Proof-of-Concept (PoC) per vulnerabilità software, sfruttando grandi modelli di linguaggio e parsing automatizzato delle basi dati.  
⚠️ **Il progetto è in fase di sviluppo: al momento non tutti gli exploit funzionano correttamente.**

---

## ✅ Requisiti

Prima di eseguire il progetto, assicurati di avere:

- [Docker](https://www.docker.com/) installato e funzionante
- [Ollama](https://ollama.com/) installato sul sistema

Successivamente, esegui i seguenti passaggi:

### 1. Scaricare l'immagine del modello

```bash
ollama pull deepseek-coder-v2:16b
```

### 2. Clonare le seguenti repository

- [Vulhub](https://github.com/vulhub/vulhub.git) — raccolta di vulnerabilità containerizzate:

```bash
git clone https://github.com/vulhub/vulhub.git
```

> ℹ️ **Nota:** segui le istruzioni contenute all'interno di ciascuna directory per avviare la vulnerabilità.

- [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub.git) — PoC aggiornati da GitHub:

```bash
git clone https://github.com/nomi-sec/PoC-in-GitHub.git
```

- [ExploitDB](https://gitlab.com/exploit-database/exploitdb.git) — database di exploit da Offensive Security:

```bash
git clone https://gitlab.com/exploit-database/exploitdb.git
```

---

### 3. Configurare il file `.env`

Crea un file `.env` nella directory principale del progetto con il seguente contenuto:

```env
NVD_API_KEY="YOUR_NVD_API_KEY"
NVD_CVE_SEARCH="https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_SEARCH="https://services.nvd.nist.gov/rest/json/cpes/2.0"
POC_IN_GITHUB="/percorso/assoluto/PoC-in-GitHub"
REPO="/percorso/assoluto/cartella-del-progetto"
```

> 🔐 **Nota:** sostituisci `YOUR_NVD_API_KEY` con la tua chiave personale ottenuta dal [sito NVD](https://nvd.nist.gov/developers/request-an-api-key).  
> 🗂️ I percorsi locali devono essere assoluti e riferiti al tuo sistema.

---

## 🚀 Esecuzione

1. **Avvia il servizio Ollama**

```bash
ollama serve
```

2. **Esegui lo script `parser.py`** per indicizzare e preparare i dati:

```bash
python parser.py
```

3. **Avvia una vulnerabilità da Vulhub**, scegliendo una directory e seguendo le istruzioni al suo interno (di solito con `docker-compose up -d`).

4. **Esegui il file principale (`main.py`)** per avviare il sistema di generazione PoC:

```bash
python main.py
```

---

## 🧪 Stato del progetto

- [x] Parsing di PoC da fonti pubbliche  
- [x] Supporto a Ollama + LLM locale  
- [ ] Generazione PoC funzionanti per ogni CVE  
- [ ] Integrazione automatica con ambienti Docker

---

## 📌 Note

- Alcune vulnerabilità potrebbero non avviarsi correttamente o essere incompatibili con la generazione attuale della PoC.

---
