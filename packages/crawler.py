from collections import deque
import requests
from bs4 import BeautifulSoup
import lxml
from urllib.parse import urljoin, urlparse


headers = {
    "User-Agent": "Mozilla/5.0"
}


def extract_forms(soup, curr_url):

    all_Forms = []
    forms = soup.find_all('form')
    for form in forms:

        raw_action = form.get('action', '')
        action_url = urljoin(curr_url, raw_action)
        method = form.get('method', 'get').lower()

        input_list=[]
        for input_tag in form.find_all(['input', 'textarea', 'button', 'select']):

            input_name = input_tag.get('name', '')
            input_type = input_tag.get('type', '')
            input_value = input_tag.get('value', '')

            input_data = {
                'name': input_name,
                'type': input_type,
                'value': input_value
            }
            input_list.append(input_data)

        form_data = {
            'found on' : curr_url,
            'action' : action_url,
            'method' : method,
            'inputs' : input_list
        }

        all_Forms.append(form_data)

    return all_Forms

def fetch_page(url):
    webpage = requests.get(url, headers=headers, timeout=10)
    return webpage

def extract_links(soup, base_url):

    base_host = urlparse(base_url).hostname

    url = [link.get('href') for link in soup.find_all('a', href=True)]
    url = [urljoin(base_url, link) for link in url]
    parsed = [urlparse(link) for link in url]


    allowed_links = filter_links(url, parsed, base_host)

    return allowed_links



def filter_links(urls, parsed_urls, base_host):

    allowed_links = []

    for raw, pars in zip(urls, parsed_urls):

        if pars.hostname == base_host and not pars.fragment:
            allowed_links.append(raw)

    return allowed_links

def crawl(start_url, max_depth=20):

    visited = set()
    queue = deque([(start_url,0)])
    found_links = set()

    crawl_data = {
        'scanned_pages' : set(),
        'discovered_endpoints' : set(),
        'forms' : []
    }

    while queue:
        curr_url, depth = queue.popleft()

        if depth > max_depth:
            continue

        if curr_url in visited:
            continue

        visited.add(curr_url)

        page = fetch_page(curr_url)

        if page.status_code != 200:
            continue

        cleaned_html = page.content.decode('utf-8', errors='replace')
        soup = BeautifulSoup(cleaned_html, 'lxml')

        crawl_data['scanned_pages'].add(curr_url)

        new_links = extract_links(soup, curr_url)
        forms = extract_forms(soup, curr_url)
        found_links.update(new_links)

        crawl_data['discovered_endpoints'].update(new_links)
        crawl_data['forms'].extend(forms)

        for link in new_links:
            if link not in visited:
                queue.append((link, depth+1))

    crawl_data["scanned_pages"] = list(crawl_data["scanned_pages"])
    crawl_data["discovered_endpoints"] = list(crawl_data["discovered_endpoints"])

    return crawl_data

