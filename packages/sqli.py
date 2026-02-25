import json

import requests
from urllib.parse import urljoin
import time

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

            response = requests.post(action, data=safe_data)
            candidate['response_length_baseline'] = len(response.text)
            candidate['response_code_baseline'] = response.status_code

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

            response = requests.get(action, params=safe_data)
            candidate['response_length_baseline'] = len(response.text)
            candidate['response_code_baseline'] = response.status_code

    return candidates

def injector(forms):
    candidates = set_baselines(forms)
    #print(candidates)

    with open('data\payloads.json', 'r') as f:
        payload = json.load(f)

    arsenal = payload['auth_bypass'] + payload['error_triggering']
    #print(arsenal)

    vulnerable_pages = []

    for candidate in candidates:

        for load in arsenal:

            vulnerable_page = {}

            method = candidate['method']
            data = {}

            if method == 'post':

                action = candidate['action']

                for cd in candidate['inputs']:

                    input_name = cd.get('name')
                    if not input_name:
                        continue

                    if cd.get('type') in ['text', 'password', 'email', 'search', 'number', 'textarea']:

                        data[input_name] = load

                    else:
                        data[input_name] = cd.get('value')

                response = requests.post(action, data=data)
                if response.status_code == 200 and len(response.text) != candidate['response_length_baseline']:
                    vulnerable_page['load'] = load
                    vulnerable_page['action'] = action
                    vulnerable_page['url'] = candidate['found on']
                    vulnerable_page['response'] = response.status_code
                    vulnerable_pages.append(vulnerable_page)

            elif method == 'get':

                action = candidate['action']

                for cd in candidate['inputs']:

                    input_name = cd.get('name')
                    if not input_name:
                        continue

                    if cd.get('type') in ['text', 'password', 'email', 'search', 'number', 'textarea']:

                        data[input_name] = load

                    else:
                        data[input_name] = cd.get('value')

                response = requests.get(action, params=data)
                if response.status_code == 200 and len(response.text) != candidate['response_length_baseline']:
                    vulnerable_page['load'] = load
                    vulnerable_page['action'] = action
                    vulnerable_page['url'] = candidate['found on']
                    vulnerable_page['response'] = response.status_code
                    vulnerable_pages.append(vulnerable_page)

    return vulnerable_pages