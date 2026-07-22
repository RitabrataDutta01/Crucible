import os
import requests

TEXT_TYPES = ['text', 'password', 'email', 'search', 'number', 'textarea']
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')


def is_real_endpoint(form):
    action = form['action']
    if not action:
        return False
    if action.startswith('javascript:'):
        return False
    if action.startswith('#'):
        return False
    return True


def is_actionable(params):
    for param in params:
        if param.get('type') in TEXT_TYPES:
            return True
    return False


def prepare_input_data(candidate, load):
    data = {}
    for cd in candidate['inputs']:
        input_name = cd.get('name')
        if not input_name:
            continue
        if cd.get('type') in TEXT_TYPES:
            data[input_name] = load
        else:
            data[input_name] = cd.get('value')
    return data


def send_request(action, method, data, session=None):
    try:
        caller = session if session else requests
        if method == 'post':
            return caller.post(action, data=data)
        return caller.get(action, params=data)
    except requests.exceptions.RequestException:
        return None
