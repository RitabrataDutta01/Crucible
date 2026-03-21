import requests, json, os, concurrent.futures
from bs4 import BeautifulSoup

current_file_path = os.path.abspath(__file__)
packages_dir = os.path.dirname(current_file_path)
PROJECT_ROOT = os.path.dirname(packages_dir)
LFI_JSON_PATH = os.path.join(PROJECT_ROOT, 'data', 'lfi.json')

global active_session

try:
    with open(LFI_JSON_PATH, 'r') as f:
              payloads = json.load(f)['lfi_payloads']
except FileNotFoundError:
    print("[-] LFI payloads file not found. Ensure 'data/lfi.json' exists.")
    payloads = []
    
def send_request(urls):
    
    url = urls['url'] 
    try:
        response = active_session.get(url, timeout=25)
        response.raise_for_status()
        return {
            "response": response,
            "payload" : urls['payload'],
            "status" : response.status_code
        }
    except requests.exceptions.RequestException as e:
        print(f"[-] Request to {url} failed: {e}")
        return None
    except requests.exceptions.Timeout:
        print(f"[-] Request to {url} timed out.")
        return None
    except Exception as e:
        print(f"[-] An error occurred while requesting {url}: {e}")
        return None
        

def primer(candidate):
    
    if not candidate or '?' not in candidate:
        return []
    
    url_list = []
    base_url, query_string = candidate.split('?', 1)
    
    params = query_string.split('&')
    
    for i in range(len(params)):
        
        test_params = params[:]
        
        if '=' in test_params[i]:
            key, _ = test_params[i].split('=', 1)
            
            for payload in payloads:
                test_params[i] = f"{key}={payload['payload']}"
                malicious_url = f"{base_url}?{'&'.join(test_params)}"
                
                url_list.append({
                    'url': malicious_url,
                    'payload': payload['signature']
                })
                
    return url_list


def injector(forms, session):
    
    global active_session
    active_session = session
    url_list = []
    findings = []
    
    for form in forms['discovered_endpoints']:
        
        print(f"[*] Processing endpoint: {form}")
        
        url_list.extend(primer(form))
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.submit(send_request, urls) for urls in url_list)
        
        for result in concurrent.futures.as_completed(results):
            res = result.result()
            if res:
                response = res['response']
                signature = res['payload']
                
                if signature.lower() in response.text.lower():
                    findings.append({'vulnerability': 'LFI', 'payload': signature, 'evidence': 'File Content Leaked'})
                    
                elif response.status_code == 500 and "java.lang" in response.text:
                    findings.append({
                        'vulnerability': 'LFI / Improper Input Validation', 
                        'url': response.url,
                        'payload': signature, 
                        'evidence': 'Triggered Server-Side Exception (500 Error)'
                    })
        
    return findings

