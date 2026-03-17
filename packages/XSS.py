import requests, json, time, os, concurrent.futures
from datetime import datetime
from config import Config

session = None
probe = """crucible'"><;"""

DANGER_TAGS = ['<script', '<img', '<iframe', '<svg', '<a ']

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
    
def check_Reflected_XSS(candidate):

    breaker = candidate.get('breaker', '')
    with open('data/XSS.json', 'r') as f:
        payload = json.load(f)

    arsenal = payload['payload']
    findings=[]
    for load in arsenal:

        mutated_load = f"{breaker}{load}"

        print(f"  [>] Testing payload: {mutated_load[:20]}.....")

        data = prepare_Input_Data(candidate, mutated_load)
        response = send_Request(candidate['action'] , candidate['method'], data, session)
        tag_count = 0
        for tag in DANGER_TAGS:
            tag_count += response.text.lower().count(tag)

        if response is not None:

            if mutated_load in response.text and tag_count>candidate.get('tags',0):
                findings.append({
                    'vulnerability type': 'Reflected XSS',
                    'context': candidate.get('type', 'Unknown'),
                    'url': candidate.get('found on', 'Unknown Source'),
                    'payload': mutated_load,
                    'endpoint': candidate['action'],
                    'method': candidate['method'],
                    'data': data
                })

                break;
            
    return findings

def injector(forms, active_session):

    global session
    session = active_session

    candidates = [f for f in forms if looks_Real_Endpoint(f) and isActionable(f['inputs'])]

    vulnerable_pages = []
    exploitable = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:

        probe = {executor.submit(reflection,c): c for c in candidates}

        for future in concurrent.futures.as_completed(probe):
            try:
                probe_report = future.result()
                if probe_report and probe_report.get('vulnerable'):
                    exploitable.append(probe_report)

            except Exception as e:
                print(f"[-] Scouting Error: {e}")

        if exploitable:
            attacks = {executor.submit(check_Reflected_XSS, t): t for t in exploitable}

            for future in concurrent.futures.as_completed(attacks):

                try:
                    findings = future.result()
                    if findings:
                        vulnerable_pages.extend(findings)
                except Exception as e:
                    print(f"[-] Attack Thread Error: {e}")

    return vulnerable_pages


def reflection(candidate):
    
    global probe
    load = probe
    findings = []

    data = prepare_Input_Data(candidate, load)
    response = send_Request(candidate['action'] , candidate['method'], data, session)
    
    if response is None:
        return None

    txt = response.text
    
    if load in txt:

        occurence_index = txt.find(load)

        start_snippet = max(0, occurence_index-15)
        preceeding_part = txt[start_snippet:occurence_index]

        rp = txt[occurence_index:occurence_index+len(load)]

        survival = {
            "lt_raw": "<" in rp,
            "gt_raw": ">" in rp,
            "quot_raw": '"' in rp,
            "apos_raw": "'" in rp,
            "semi_raw": ";" in rp,
            "lt_encoded": "&lt;" in rp or "&#60;" in rp,
            "quot_encoded": "&quot;" in rp or "&#34;" in rp
        }

        strategy = {"vulnerable": False, "type": "Unknown", "breaker": "", 'tags': 0}

        if preceeding_part.strip().endswith('>'):
            
            strategy["type"] = "HTML"
            if survival["lt_raw"] and survival["gt_raw"]:
                strategy['breaker'] = ""
                strategy['vulnerable'] = True
                strategy['tags'] = sum([txt.lower().count(tag) for tag in DANGER_TAGS])

        elif '=' in preceeding_part or '="' in preceeding_part:
            
            strategy["type"] = "Attribute"

            if survival["quot_raw"] and survival["gt_raw"]:
                strategy["vulnerable"] = True
                strategy["breaker"] = '">'
                strategy['tags'] = sum([txt.lower().count(tag) for tag in DANGER_TAGS])

        elif "var" in preceeding_part or "script" in preceeding_part.lower():
            strategy["type"] = "Javascript"

            if survival["apos_raw"] and survival["semi_raw"]:
                strategy["vulnerable"] = True
                strategy["breaker"] = "';"
                strategy['tags'] = sum([txt.lower().count(tag) for tag in DANGER_TAGS])

        candidate.update(strategy)
        return candidate

    return None
