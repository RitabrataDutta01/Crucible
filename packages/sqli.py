import json, requests, os, time, concurrent.futures
from datetime import datetime
import numpy as np

active_session = None

try:
    with open('data/payloads.json', 'r') as f:
        PAYLOADS_DB = json.load(f)
except FileNotFoundError:
    PAYLOADS_DB = {'auth_bypass': [], 'time_based': []}
    print("[-] Warning: data/payloads.json not found.")

try:
    with open('data/fuzzdb_sqli_arsenal.json', 'r') as f:
        FUZZDB_ARSENAL = [item['payload'] for item in json.load(f)]
except FileNotFoundError:
    FUZZDB_ARSENAL = []
    print("[-] Warning: data/fuzzdb_sqli_arsenal.json not found.")

try:
    with open('data/errorSignature.json', 'r') as fn:
        ERROR_SIGNATURES = json.load(fn)
except FileNotFoundError:
    ERROR_SIGNATURES = []
    print("[-] Warning: data/errorSignature.json not found.")

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

def set_baselines(forms):

    candidates = sqli_scanner(forms)

    for candidate in candidates:

        method = candidate['method']

        safe_data = prime_dummy(candidate)
        action = candidate['action']

        if method == 'post':

            response = send_Request(action, 'post', safe_data, active_session)
            if response is not None:
                candidate['response_length_baseline'] = len(response.text)
                candidate['response_code_baseline'] = response.status_code
                candidate['time_elapsed'] = response.elapsed.total_seconds()
                
                durations = []
                for _ in range(3):
                    start = time.perf_counter()
                    response = send_Request(action, 'post', safe_data, active_session)
                    duration = time.perf_counter() - start
                    durations.append(duration)
            
                candidate['server_delay_baseline'] = np.std(durations)
                candidate['time_mean'] = np.mean(durations)
                candidate['jitter'] = max(0.05, candidate['server_delay_baseline']*3)

            else:
                candidate['response_length_baseline'] = 0
                candidate['response_code_baseline'] = 0
                candidate['time_elapsed'] = 0
                candidate['server_delay_baseline'] = 0
                candidate['time_mean'] = 0
                candidate['jitter'] = 0
            
            
        elif method == 'get':

            response = send_Request(action, 'get', safe_data, active_session)

            if response is not None:
                candidate['response_length_baseline'] = len(response.text)
                candidate['response_code_baseline'] = response.status_code
                candidate['time_elapsed'] = response.elapsed.total_seconds()
                
                durations = []
                for _ in range(3):
                    start = time.perf_counter()
                    response = send_Request(action, 'get', safe_data, active_session)
                    duration = time.perf_counter() - start
                    durations.append(duration)
            
                candidate['server_delay_baseline'] = np.std(durations)
                candidate['time_mean'] = np.mean(durations)
                candidate['jitter'] = max(0.05, np.std(durations) * 3)
                
            else:
                candidate['response_length_baseline'] = 0
                candidate['response_code_baseline'] = 0
                candidate['time_elapsed'] = 0
                candidate['server_delay_baseline'] = 0
                candidate['time_mean'] = 0
                candidate['jitter'] = 0
                
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

    arsenal = PAYLOADS_DB.get('auth_bypass', [])
    findings = []

    for load in arsenal:

        print(f"  [>] Testing payload auth")

        data = prepare_Input_Data(candidate, load)
        response = send_Request(candidate['action'] , candidate['method'], data, active_session)
        print(f"[DEBUG] URL: {response.url} | Status: {response.status_code}")

        if response is None:
            continue
        
        length = abs(len(response.text) - candidate['response_length_baseline'])
        change = length > (candidate['response_length_baseline']*0.1)
        
        success_keywords = ["logout", "sign off", "my account", "welcome"]
        found_success = any(word in response.text.lower() for word in success_keywords)

        if response.status_code == 200 and (change or found_success):
            finding = {
                'url' : candidate['found on'],
                'vulnerability type': 'Auth Bypass SQLI',
                'payload': load,
                'severity': 'Critical',
                'evidence': f"Auth bypass successful on {candidate.get('action', 'target')} using payload: {load}"
            }

            findings.append(finding)
            break

        elif response.status_code == 500:
            finding = {
                'url' : candidate['found on'],
                'vulnerability type': 'Auth Bypass SQLI',
                'payload': load,
                'severity': 'Critical',
                'evidence': f"Potential server crash(500) on {candidate.get('action', 'target')} using payload: {load}",
                'status': response.status_code
            }

            findings.append(finding)
            break
    return findings

def check_Error_Based(candidate):

    arsenal = FUZZDB_ARSENAL
    findings = []
    unique_hits = {}

    for load in arsenal:

        print(f"  [>] Testing payload error")

        data = prepare_Input_Data(candidate, load)
        response = send_Request(candidate['action'] , candidate['method'], data, active_session)
        print(f"[DEBUG] URL: {response.url} | Status: {response.status_code}")

        if response is None:
            continue

        if any(error.lower() in response.text.lower() for error in ERROR_SIGNATURES):
            if candidate['found on'] not in unique_hits:
                unique_hits[candidate['found on']] = 1
                finding = {
                    'url' : candidate['found on'],
                    'vulnerability type': 'Error Based SQLI',
                    'payload': load,
                    'severity': 'Critical',
                    'evidence': f"Server error by {candidate['found on']}",
                    'status': response.status_code
                }
                findings.append(finding)
                break

    return findings

def check_time_Based(candidate):

    arsenal = PAYLOADS_DB.get('time_based', [])
    findings = []

    for load in arsenal:
        print(f"  [>] Testing payload time")
        
        start_clock = time.perf_counter()

        data = prepare_Input_Data(candidate, load['payload'])
        response = send_Request(candidate['action'] , candidate['method'], data, active_session)
        print(f"[DEBUG] URL: {response.url} | Status: {response.status_code}")
        
        
        duration = time.perf_counter() - start_clock

        if response is None:
            continue

        threshold = candidate['time_mean'] + candidate['jitter'] + load.get('delay', 5) - 1.0
        if duration >= threshold:

            finding = {
                'url' : candidate['found on'],
                'vulnerability type': 'Time Based SQLI',
                'payload': load['payload'],
                'severity': 'Critical',
                'evidence': f"Server delayed by {duration}s"
            }
            findings.append(finding)
            break

    return findings

def test_single_candidate(candidate):

    results = []
    results.extend(check_Auth_Bypass(candidate))
    results.extend(check_Error_Based(candidate))
    results.extend(check_time_Based(candidate))
    return results

def injector(forms, session):
    
    global active_session 
    active_session = session
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

    return vulnerable_pages