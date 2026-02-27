import json, requests, os, time
from datetime import datetime

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

            response = send_Request(action, 'post', safe_data)
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

            response = send_Request(action, 'get', safe_data)

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

def send_Request(action, method, data):

    try:
        #time.sleep(5)
        if method == 'post':
            return requests.post(action, data=data, timeout=30)
        return requests.get(action, params=data, timeout=30)
    except requests.exceptions.RequestException:
        return None

def check_Auth_Bypass(candidate):

    with open('data/payloads.json', 'r') as f:
        payload = json.load(f)

    arsenal = payload['auth_bypass']
    findings=[]

    for load in arsenal:

        data = prepare_Input_Data(candidate, load)
        response = send_Request(candidate['action'] , candidate['method'], data)

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

        data = prepare_Input_Data(candidate, load)
        response = send_Request(candidate['action'] , candidate['method'], data)

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

        data = prepare_Input_Data(candidate, load['payload'])
        response = send_Request(candidate['action'] , candidate['method'], data)

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

def injector(forms):
    candidates = set_baselines(forms)

    vulnerable_pages = []

    for candidate in candidates:

        vulnerable_pages.extend(check_Auth_Bypass(candidate))
        vulnerable_pages.extend(check_Error_Based(candidate))
        vulnerable_pages.extend(check_time_Based(candidate))

    if vulnerable_pages:
        if not os.path.exists('reports'):
            os.makedirs('reports')

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"reports/scan_report_{timestamp}.json"

        with open(log_filename, 'w') as log_file:
            json.dump(vulnerable_pages, log_file, indent=4)


    return vulnerable_pages