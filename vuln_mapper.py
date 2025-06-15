import requests
import logging
import time
from typing import Dict, Any, List, Optional
from difflib import get_close_matches
from packaging import version as vparser
import re
import os

# Config
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_CVE_SEARCH = os.getenv("NVD_CVE_SEARCH")
NVD_CPE_SEARCH = os.getenv("NVD_CPE_SEARCH")

logging.basicConfig(
    format="[%(levelname)s][%(asctime)s] %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("vuln_mapper")


def safe_request(url, params, headers, retries=3, sleep_time=1):
    for i in range(retries):
        try:
            res = requests.get(url, params=params, headers=headers, timeout=10)
            if res.status_code == 200:
                return res
            elif res.status_code == 429:
                logger.warning("Rate limit reached. Waiting...")
                time.sleep(sleep_time * (i + 1))
            else:
                logger.warning(f"Unexpected status code: {res.status_code}")
                return None
        except Exception as e:
            logger.warning(f"Request error: {e}")
            time.sleep(sleep_time * (i + 1))
    return None


def fetch_all_nvd_results(url, params, headers):
    results = []
    start_index = 0
    results_per_page = params.get("resultsPerPage", 200)
    while True:
        p = params.copy()
        p["startIndex"] = start_index
        res = safe_request(url, p, headers)
        if not res:
            break
        data = res.json()
        items = data.get("vulnerabilities") or data.get("products") or []
        if not items:
            break
        results.extend(items)
        total_results = int(data.get("totalResults", 0))
        if len(results) >= total_results:
            break
        start_index += results_per_page
    return results


def normalize_version(version_str: str) -> str:
    match = re.match(r'^(\d+\.\d+(?:\.\d+)?)(?:[^\d].*)?$', version_str.strip())
    if match:
        return match.group(1)
    for sep in ['.', '-', '_']:
        parts = version_str.split(sep)
        if all(p.isdigit() for p in parts[:2]):
            return '.'.join(parts[:3])
    return version_str.strip()


def is_version_in_range(target_version: str, match: dict) -> bool:
    try:
        t = vparser.parse(target_version)
        vs = match.get("versionStartIncluding") or match.get("versionStartExcluding")
        ve = match.get("versionEndIncluding") or match.get("versionEndExcluding")
        if vs:
            cmp = vparser.parse(vs)
            if "Including" in match and t < cmp:
                return False
            elif "Excluding" in match and t <= cmp:
                return False
        if ve:
            cmp = vparser.parse(ve)
            if "Including" in match and t > cmp:
                return False
            elif "Excluding" in match and t >= cmp:
                return False
        return True
    except Exception as e:
        logger.error(f"[version-range-check-error] {e}")
        return False


def is_cve_version_match(cve, product_name, target_version, fuzzy=False):
    cve_configurations = cve.get("cve", {}).get("configurations", []) or cve.get("configurations", [])
    for conf in cve_configurations:
        for node in conf.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe_uri = cpe_match.get("criteria") or cpe_match.get("cpe23Uri", "")
                if (product_name.replace(" ", "_") in cpe_uri or product_name in cpe_uri or
                        (fuzzy and get_close_matches(product_name.replace(" ", "_"), [cpe_uri], n=1, cutoff=0.6))):
                    if not cpe_match.get("vulnerable", False):
                        continue
                    if is_version_in_range(target_version, cpe_match):
                        return True
    cve_desc = (cve.get("cve", {}).get("descriptions", [{}])[0].get("value", "") or
                cve.get("description", ""))
    if target_version in cve_desc:
        return True
    if fuzzy and not target_version in cve_desc:
        return any(target_version in s for s in cve_desc.split())
    return False


def extract_cve_info(item) -> Dict[str, Any]:
    if "cve" in item:
        cve_data = item["cve"]
        cve_id = cve_data.get("id")
        descs = cve_data.get("descriptions", [])
        desc = descs[0]["value"] if descs else ""
    else:
        cve_id = item.get("cve_id")
        desc = item.get("description", "")
    return {
        "cve_id": cve_id,
        "description": desc
    }


def get_cves_for_service(product_name: str, target_version: str, fuzzy: bool = False) -> List[Dict[str, Any]]:
    headers = {"apiKey": NVD_API_KEY}
    params = {"keywordSearch": product_name, "resultsPerPage": 200}
    vulns = fetch_all_nvd_results(NVD_CVE_SEARCH, params, headers)
    results = []
    for item in vulns:
        if not is_cve_version_match(item, product_name, target_version, fuzzy=fuzzy):
            continue
        results.append(extract_cve_info(item))
    return results


def find_cpe_for_service(product_name: str, version: str, fuzzy: bool = False) -> Optional[str]:
    headers = {"apiKey": NVD_API_KEY}
    query = f"{product_name} {version}"
    params = {"keywordSearch": query, "resultsPerPage": 20}
    res = safe_request(NVD_CPE_SEARCH, params=params, headers=headers)
    if not res:
        return None
    data = res.json()
    matches = data.get("products", [])
    for match in matches:
        cpe_name = match.get("cpe", {}).get("cpeName")
        if cpe_name:
            name_part = cpe_name.split(":")[-2].replace("_", " ")
            if (fuzzy and get_close_matches(product_name, [name_part], n=1, cutoff=0.6)) or (version in cpe_name):
                logger.info(f"CPE found: {cpe_name}")
                return cpe_name
    return None


def get_cves_for_cpe(cpe: str, version: str, fuzzy: bool = False) -> List[Dict[str, Any]]:
    headers = {"apiKey": NVD_API_KEY}
    params = {"cpeName": cpe, "resultsPerPage": 200}
    vulns = fetch_all_nvd_results(NVD_CVE_SEARCH, params, headers)
    results = []
    for item in vulns:
        if not is_cve_version_match(item, cpe, version, fuzzy=fuzzy):
            continue
        results.append(extract_cve_info(item))
    return results


def guess_underlying_product(ip: str, port: int) -> str:
    url = f"http://{ip}:{port}"
    try:
        res = requests.get(url, timeout=5)
        content = res.text.lower()
        headers = res.headers

        if "apache druid" in content or "druid.io" in content:
            return "apache druid"
        if "grafana" in content:
            return "grafana"
        if "kibana" in content:
            return "kibana"
        if "elasticsearch" in content:
            return "elasticsearch"
        if "prometheus" in content:
            return "prometheus"

        server_header = headers.get("Server", "").lower()
        if "druid" in server_header:
            return "apache druid"
        if "kibana" in server_header:
            return "kibana"
        if "grafana" in server_header:
            return "grafana"
        if "tomcat" in server_header:
            return "apache tomcat"

    except Exception as e:
        logger.warning(f"Errore durante il probing HTTP di {url}: {e}")

    return ""


def map_services_to_vulns(service: Dict[str, Any], fuzzy: bool = False) -> List[Dict[str, Any]]:
    product = (service.get("product") or service.get("name", "")).lower().replace("httpd", "http server")
    version = normalize_version(service.get("version", ""))
    product = " ".join(product.split())

    # Tentativo di dedurre il vero software dietro (es. apache druid)
    guessed = guess_underlying_product(service["ip"], service["port"])
    if guessed:
        logger.info(f"Guessed product from HTTP content: {guessed}")
        product = guessed

    if not version:
        logger.warning(f"No version specified for the service: {service}")

    logger.info(f"Searching for CPE for: {product} {version}")
    cpe = find_cpe_for_service(product, version, fuzzy=fuzzy)
    all_cves = []

    if cpe:
        cves = get_cves_for_cpe(cpe, version, fuzzy=fuzzy)
        if cves:
            logger.info(f"Found {len(cves)} CVEs via CPE")
            all_cves += cves

    logger.info("CPE not found or no CVEs for CPE, falling back to keyword search")
    cves = get_cves_for_service(product, version, fuzzy=fuzzy)
    all_cves += cves

    filtered, seen = [], set()
    for cve in all_cves:
        if cve["cve_id"] not in seen:
            filtered.append(cve)
            seen.add(cve["cve_id"])
    if not filtered:
        logger.info("No CVE found.")
    return filtered
