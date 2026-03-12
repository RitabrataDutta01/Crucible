import requests, json, time, os, concurrent.futures
from datetime import datetime
from config import Config

session = None

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

    with open('data/XSS.json', 'r') as f:
        payload = json.load(f)

    arsenal = payload['payload']
    findings=[]

    for load in arsenal:

        print(f"  [>] Testing payload XSS")

        data = prepare_Input_Data(candidate, load)
        response = send_Request(candidate['action'] , candidate['method'], data, session)

        if response is not None:

            if load in response.text:
                findings.append({
                    'vulnerability type': 'Reflected XSS',
                    'url': candidate.get('found on', 'Unknown Source'),
                    'payload': load,
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

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:

        future_to_xss = {executor.submit(check_Reflected_XSS, c): c for c in candidates}

        for future in concurrent.futures.as_completed(future_to_xss):
            try:
                findings = future.result()
                if findings:
                    vulnerable_pages.extend(findings)
            except Exception as e:
                print(f"[-] XSS Thread error: {e}")

    if vulnerable_pages:
        if not os.path.exists('reports'):
            os.makedirs('reports')

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"reports/scan_report_{timestamp}.json"

        with open(log_filename, 'w') as log_file:
            json.dump(vulnerable_pages, log_file, indent=4)


    return vulnerable_pages


def relfection()