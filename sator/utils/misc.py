import requests
import hashlib


def get_file_content_from_url(url: str):
    request = requests.get(url)

    if request.status_code == 200:
        return request.text
    else:
        raise Exception(f'Request code {request.status_code} for {url}')


def get_digest(string: str):
    return hashlib.md5(string.encode('utf-8')).hexdigest()
