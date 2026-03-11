import json, requests, os, time, concurrent.futures
from datetime import datetime

session = requests.Session()

def looks_Real_Endpoint(form):

    action = form['action']
    if not action:
        return False

    if action.startswith('javascript:'):
        return False

    if action.startswith('#'):
        return False

    return True

def isActionable(params):

    for param in params:

        if param.get('type') in ['text', 'password', 'email', 'search', 'number', 'textarea']:
            return True

    return False

def sqli_scanner(forms):

    candidates = []
    seen_signature = set()
    for form in forms:

        if not looks_Real_Endpoint(form):
            continue

        if not isActionable(form['inputs']):
            continue


        signature = f"{form['method']}:{form['action']}"
        if signature in seen_signature:
            continue

        seen_signature.add(signature)
        candidates.append(form)

    return candidates

def set_baselines(forms):

    candidates = sqli_scanner(forms)

    for candidate in candidates:

        method = candidate['method']

        safe_data = {}

        if method == 'post':

            action = candidate['action']

            for cd in candidate['inputs']:

                input_name = cd.get('name')
                if not input_name:
                    continue

                if cd.get('type') in ['text', 'password', 'email', 'search', 'number', 'textarea']:
                    safe_data[input_name] = 'Dummy'
                else:
                    safe_data[input_name] = cd.get('value')

            response = send_Request(action, 'post', safe_data, session)
            if response is not None:
                candidate['response_length_baseline'] = len(response.text)
                candidate['response_code_baseline'] = response.status_code
            else:
                candidate['response_length_baseline'] = 0
                candidate['response_code_baseline'] = 0

        elif method == 'get':

            action = candidate['action']

            for cd in candidate['inputs']:

                input_name = cd.get('name')
                if not input_name:
                    continue

                if cd.get('type') in ['text', 'password', 'email', 'search', 'number', 'textarea']:
                    safe_data[input_name] = 'Dummy'
                else:
                    safe_data[input_name] = cd.get('value')

            response = send_Request(action, 'get', safe_data, session)

            if response is not None:
                candidate['response_length_baseline'] = len(response.text)
                candidate['response_code_baseline'] = response.status_code
            else:
                candidate['response_length_baseline'] = 0
                candidate['response_code_baseline'] = 0

    return candidates


def prepare_Input_Data(candidate, load):

    data = {}
    for cd in candidate['inputs']:

        input_name = cd.get('name')
        if not input_name:
            continue

        text_types = ['text', 'password', 'email', 'search', 'number', 'textarea']

        if cd.get('type') in text_types:
            data[input_name] = load
        else:
            data[input_name] = cd.get('value')

    return data

def send_Request(action, method, data, session = None):

    try:
        caller = session if session else requests
        if method == 'post':
            return caller.post(action, data=data)
        return caller.get(action, params=data)
    except requests.exceptions.RequestException:
        return None

def check_Auth_Bypass(candidate):

    with open('data/payloads.json', 'r') as f:
        payload = json.load(f)

    arsenal = payload['auth_bypass']
    findings=[]

    for load in arsenal:

        print(f"  [>] Testing payload auth")

        data = prepare_Input_Data(candidate, load)
        response = send_Request(candidate['action'] , candidate['method'], data, session)

        if response is None:
            continue

        if response.status_code == 200 and len(response.text) > candidate['response_length_baseline']:
            finding = {
                'url' : candidate['found on'],
                'vulnerability type': 'Auth Bypass SQLI',
                'payload': load,
                'severity': 'Critical',
                'evidence': f"Auth bypass successful on {candidate.get('action', 'target')} using payload: {load}"
            }

            findings.append(finding)
            break
    return findings

def check_Error_Based(candidate):

    with open('data/fuzzdb_sqli_arsenal.json', 'r') as f:
        fuzzdb_data = json.load(f)

    with open('data/errorSignature.json', 'r') as fn:
        errorSignature = json.load(fn)

    arsenal = [item['payload'] for item in fuzzdb_data]

    findings = []
    unique_hits = {}
    for load in arsenal:

        print(f"  [>] Testing payload error")

        data = prepare_Input_Data(candidate, load)
        response = send_Request(candidate['action'] , candidate['method'], data, session)

        if response is None:
            continue

        if any(error.lower() in response.text.lower() for error in errorSignature):
            if candidate['found on'] not in unique_hits:
                unique_hits[candidate['found on']] = 1
                finding = {
                    'url' : candidate['found on'],
                    'vulnerability type': 'Error Based SQLI',
                    'payload': load,
                    'severity': 'Critical',
                    'evidence': f"Server error by {candidate['found on']}"
                }
                findings.append(finding)
                break

    return findings

def check_time_Based(candidate):

    with open('data/payloads.json', 'r') as f:
        payload = json.load(f)

    arsenal = payload['time_based']
    findings = []

    for load in arsenal:
        print(f"  [>] Testing payload time")

        data = prepare_Input_Data(candidate, load['payload'])
        response = send_Request(candidate['action'] , candidate['method'], data, session)

        if response is None:
            continue
        duration = response.elapsed.total_seconds()
        if duration >= load['delay']:

            finding = {
                'url' : candidate['found on'],
                'vulnerability type': 'Time Based SQLI',
                'payload': load['payload'],
                'severity': 'Critical',
                'evidence': f"Server delayed by {duration}s"
            }
            findings.append(finding)

    return findings

def test_single_candidate(candidate):

    results = []
    results.extend(check_Auth_Bypass(candidate))
    results.extend(check_Error_Based(candidate))
    results.extend(check_time_Based(candidate))
    return results

def injector(forms):
    candidates = set_baselines(forms)

    vulnerable_pages = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_vuln = {executor.submit(test_single_candidate, c): c for c in candidates}

        for future in concurrent.futures.as_completed(future_to_vuln):
            try:
                data = future.result()
                if data:
                    vulnerable_pages.extend(data)
            except Exception as e:
                print(f"[-] Thread error on candidate: {e}")

    if vulnerable_pages:
        if not os.path.exists('reports'): os.makedirs('reports')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"reports/scan_report_{timestamp}.json"
        with open(log_filename, 'w') as log_file:
            json.dump(vulnerable_pages, log_file, indent=4)


    return vulnerable_pages