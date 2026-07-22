import json, os, concurrent.futures, re, time
from .utils import is_real_endpoint, is_actionable, prepare_input_data, send_request, DATA_DIR
from config import ScanConfig

try:
    with open(os.path.join(DATA_DIR, 'payloads.json'), 'r') as f:
        PAYLOADS_DB = json.load(f)
except FileNotFoundError:
    PAYLOADS_DB = {'auth_bypass': [], 'time_based': []}
    print("[-] Warning: data/payloads.json not found.")

try:
    with open(os.path.join(DATA_DIR, 'fuzzdb_sqli_arsenal.json'), 'r') as f:
        FUZZDB_ARSENAL = [item['payload'] for item in json.load(f)]
except FileNotFoundError:
    FUZZDB_ARSENAL = []
    print("[-] Warning: data/fuzzdb_sqli_arsenal.json not found.")

try:
    with open(os.path.join(DATA_DIR, 'errorSignature.json'), 'r') as fn:
        raw = json.load(fn)
        ERROR_PATTERNS = []
        for pattern_list in raw.values():
            for pattern in pattern_list:
                ERROR_PATTERNS.append(re.compile(pattern, re.IGNORECASE))
except FileNotFoundError:
    ERROR_PATTERNS = []
    print("[-] Warning: data/errorSignature.json not found.")


def filter_candidates(forms):
    candidates = []
    seen_signature = set()
    for form in forms:
        if not is_real_endpoint(form):
            continue
        if not is_actionable(form['inputs']):
            continue

        signature = f"{form['method']}:{form['action']}"
        if signature in seen_signature:
            continue

        seen_signature.add(signature)
        candidates.append(form)

    return candidates


def prime_dummy(candidate):
    safe_data = {}
    for cd in candidate['inputs']:
        input_name = cd.get('name')
        if not input_name:
            continue
        if cd.get('type') in ['text', 'password', 'email', 'search', 'number', 'textarea']:
            safe_data[input_name] = 'Dummy'
        else:
            safe_data[input_name] = cd.get('value')
    return safe_data


def set_baselines(forms, session):
    candidates = filter_candidates(forms)

    for candidate in candidates:
        safe_data = prime_dummy(candidate)
        response = send_request(candidate['action'], candidate['method'], safe_data, session)
        if response is not None:
            candidate['response_length_baseline'] = len(response.text)
            candidate['response_code_baseline'] = response.status_code
            candidate['time_elapsed'] = response.elapsed.total_seconds()
        else:
            candidate['response_length_baseline'] = 0
            candidate['response_code_baseline'] = 0
            candidate['time_elapsed'] = 0

    return candidates


def check_auth_bypass(candidate, session):
    arsenal = PAYLOADS_DB.get('auth_bypass', [])
    findings = []

    for load in arsenal:
        print(f"  [>] Testing payload auth")

        data = prepare_input_data(candidate, load)
        response = send_request(candidate['action'], candidate['method'], data, session)

        if response is None:
            continue

        time.sleep(ScanConfig.RATE_LIMIT_DELAY)

        print(f"[DEBUG] URL: {response.url} | Status: {response.status_code}")

        if response.status_code == 200 and len(response.text) > candidate['response_length_baseline']:
            finding = {
                'url': candidate['found_on'],
                'vulnerability_type': 'Auth Bypass SQLI',
                'payload': load,
                'severity': 'Critical',
                'evidence': f"Auth bypass successful on {candidate.get('action', 'target')} using payload: {load}"
            }
            findings.append(finding)
            break

        if response.status_code == 500:
            finding = {
                'url': candidate['found_on'],
                'vulnerability_type': 'Auth Bypass SQLI',
                'payload': load,
                'severity': 'Critical',
                'evidence': f"Auth bypass successful on {candidate.get('action', 'target')} using payload: {load}",
                'status': response.status_code
            }
            findings.append(finding)
            break

    return findings


def check_error_based(candidate, session):
    arsenal = FUZZDB_ARSENAL
    findings = []
    reported_urls = set()

    for load in arsenal:
        print(f"  [>] Testing payload error")

        data = prepare_input_data(candidate, load)
        response = send_request(candidate['action'], candidate['method'], data, session)

        if response is None:
            continue

        time.sleep(ScanConfig.RATE_LIMIT_DELAY)

        print(f"[DEBUG] URL: {response.url} | Status: {response.status_code}")

        if any(p.search(response.text) for p in ERROR_PATTERNS):
            if candidate['found_on'] not in reported_urls:
                reported_urls.add(candidate['found_on'])
                finding = {
                    'url': candidate['found_on'],
                    'vulnerability_type': 'Error Based SQLI',
                    'payload': load,
                    'severity': 'Critical',
                    'evidence': f"Server error by {candidate['found_on']}",
                    'status': response.status_code
                }
                findings.append(finding)
                break

    return findings


def check_time_based(candidate, session):
    arsenal = PAYLOADS_DB.get('time_based', [])
    findings = []

    for load in arsenal:
        print(f"  [>] Testing payload time")

        data = prepare_input_data(candidate, load['payload'])
        response = send_request(candidate['action'], candidate['method'], data, session)

        if response is None:
            continue

        time.sleep(ScanConfig.RATE_LIMIT_DELAY)

        print(f"[DEBUG] URL: {response.url} | Status: {response.status_code}")
        duration = response.elapsed.total_seconds()

        threshold = candidate['time_elapsed'] + 2.0 + load['delay']
        if duration >= threshold:
            finding = {
                'url': candidate['found_on'],
                'vulnerability_type': 'Time Based SQLI',
                'payload': load['payload'],
                'severity': 'Critical',
                'evidence': f"Server delayed by {duration}s"
            }
            findings.append(finding)

    return findings


def test_single_candidate(candidate, session):
    results = []
    results.extend(check_auth_bypass(candidate, session))
    results.extend(check_error_based(candidate, session))
    results.extend(check_time_based(candidate, session))
    return results


def injector(forms, session):
    candidates = set_baselines(forms, session)

    vulnerable_pages = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=ScanConfig.THREAD_WORKERS) as executor:
        future_to_vuln = {executor.submit(test_single_candidate, c, session): c for c in candidates}

        for future in concurrent.futures.as_completed(future_to_vuln):
            try:
                data = future.result()
                if data:
                    vulnerable_pages.extend(data)
            except Exception as e:
                print(f"[-] Thread error on candidate: {e}")

    return vulnerable_pages
