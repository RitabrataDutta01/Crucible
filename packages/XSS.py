import json, os, concurrent.futures, time
from .utils import is_real_endpoint, is_actionable, prepare_input_data, send_request, DATA_DIR
from config import ScanConfig

probe = """crucible'"><;"""

try:
    with open(os.path.join(DATA_DIR, 'XSS.json'), 'r') as f:
        XSS_ARSENAL = json.load(f)['payload']
except FileNotFoundError:
    XSS_ARSENAL = []
    print("[-] Warning: data/XSS.json not found.")


def check_reflected_xss(candidate, active_session):
    breaker = candidate.get('breaker', '')
    arsenal = XSS_ARSENAL
    findings = []

    for load in arsenal:
        mutated_load = f"{breaker}{load}"

        print(f"  [>] Testing payload: {mutated_load[:20]}.....")

        data = prepare_input_data(candidate, mutated_load)
        response = send_request(candidate['action'], candidate['method'], data, active_session)
        
        if response is None:
            return None

        time.sleep(ScanConfig.RATE_LIMIT_DELAY)

        ct = response.headers.get('Content-Type', '')
        if 'text/html' not in ct and 'application/xhtml+xml' not in ct:
            return None

        if mutated_load in response.text:
                findings.append({
                    'vulnerability_type': 'Reflected XSS',
                    'context': candidate.get('type', 'Unknown'),
                    'url': candidate.get('found_on', 'Unknown Source'),
                    'payload': mutated_load,
                    'endpoint': candidate['action'],
                    'method': candidate['method'],
                    'data': data
                })
                break

    return findings


def injector(forms, active_session):
    candidates = [f for f in forms if is_real_endpoint(f) and is_actionable(f['inputs'])]

    vulnerable_pages = []
    exploitable = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=ScanConfig.THREAD_WORKERS) as executor:
        probe_futures = {executor.submit(check_reflection, c, active_session): c for c in candidates}

        for future in concurrent.futures.as_completed(probe_futures):
            try:
                probe_report = future.result()
                if probe_report and probe_report.get('vulnerable'):
                    exploitable.append(probe_report)
            except Exception as e:
                print(f"[-] Scouting Error: {e}")

        if exploitable:
            attacks = {executor.submit(check_reflected_xss, t, active_session): t for t in exploitable}

            for future in concurrent.futures.as_completed(attacks):
                try:
                    findings = future.result()
                    if findings:
                        vulnerable_pages.extend(findings)
                except Exception as e:
                    print(f"[-] Attack Thread Error: {e}")

    return vulnerable_pages


def check_reflection(candidate, active_session):
    load = probe

    data = prepare_input_data(candidate, load)
    response = send_request(candidate['action'], candidate['method'], data, active_session)
    
    if response is None:
        return None

    time.sleep(ScanConfig.RATE_LIMIT_DELAY)

    ct = response.headers.get('Content-Type','')
    if 'text/html' not in ct and 'application/xhtml+xml' not in ct:
        return None

    txt = response.text

    if load in txt:
        occurrence_index = txt.find(load)
        start_snippet = max(0, occurrence_index - 15)
        preceding_part = txt[start_snippet:occurrence_index]

        rp = txt[occurrence_index:occurrence_index + len(load)]

        survival = {
            "lt_raw": "<" in rp,
            "gt_raw": ">" in rp,
            "quot_raw": '"' in rp,
            "apos_raw": "'" in rp,
            "semi_raw": ";" in rp,
            "lt_encoded": "&lt;" in rp or "&#60;" in rp,
            "quot_encoded": "&quot;" in rp or "&#34;" in rp
        }

        strategy = {"vulnerable": False, "type": "Unknown", "breaker": ""}

        if preceding_part.strip().endswith('>'):
            strategy["type"] = "HTML"
            if survival["lt_raw"] and survival["gt_raw"]:
                strategy['breaker'] = ""
                strategy['vulnerable'] = True

        elif '=' in preceding_part or '="' in preceding_part:
            strategy["type"] = "Attribute"
            if survival["quot_raw"] and survival["gt_raw"]:
                strategy["vulnerable"] = True
                strategy["breaker"] = '">'

        elif "var" in preceding_part or "script" in preceding_part.lower():
            strategy["type"] = "Javascript"
            if survival["apos_raw"] and survival["semi_raw"]:
                strategy["vulnerable"] = True
                strategy["breaker"] = "';"
        else:
            strategy["type"] = "TextContent"
            if survival["lt_raw"] and survival["gt_raw"]:
                strategy["vulnerable"] = True

        candidate.update(strategy)
        return candidate

    return None
