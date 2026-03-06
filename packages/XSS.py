import requests, json, time, os
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
            return requests.post(action, data=data)
        return requests.get(action, params=data)
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
        response = send_Request(candidate['action'] , candidate['method'], data)

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

def injector(forms):

    candidates = [f for f in forms if looks_Real_Endpoint(f) and isActionable(f['inputs'])]

    vulnerable_pages = []

    for candidate in candidates:

        vulnerable_pages.extend(check_Reflected_XSS(candidate))

    if vulnerable_pages:
        if not os.path.exists('reports'):
            os.makedirs('reports')

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"reports/scan_report_{timestamp}.json"

        with open(log_filename, 'w') as log_file:
            json.dump(vulnerable_pages, log_file, indent=4)


    return vulnerable_pages