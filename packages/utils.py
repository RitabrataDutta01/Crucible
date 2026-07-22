import os
import requests
from urllib.parse import urlparse
from config import ScanConfig
import socket, ipaddress

TEXT_TYPES = ['text', 'password', 'email', 'search', 'number', 'textarea']
CSRF_KEYWORDS = ['csrf', '_token', 'authenticity_token', 'csrf_token', '__csrf_magic',
                 'token', 'nonce', '_wpnonce', 'xsrf-token']
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
        if any(kw in input_name.lower() for kw in CSRF_KEYWORDS):
            data[input_name] = cd.get('value', '')
        elif cd.get('type') in TEXT_TYPES:
            data[input_name] = load
        else:
            data[input_name] = cd.get('value')
    return data


def send_request(action, method, data, session=None):
    try:
        caller = session if session else requests
        if method == 'post':
            return caller.post(action, data=data, timeout=ScanConfig.TIMEOUT)
        return caller.get(action, params=data, timeout=ScanConfig.TIMEOUT)
    except requests.exceptions.RequestException:
        return None

def url_validator(target_url):

    parsed_url = urlparse(target_url)

    if parsed_url.scheme not in ('http', 'https'):
        return "Invalid URL scheme"

    hostname = parsed_url.hostname

    if hostname:

        try:

            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.is_private and not os.environ.get('CRUCIBLE_ALLOW_PRIVATE'):
                return "Error: Private IP detected!"

        except socket.gaierror:
            return "Error: Could not resolve hostname."
    
    else:
        return "Error: No hostname found in URL."

