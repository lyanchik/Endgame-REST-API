import requests
import re
import simplejson
import json



def request_method(url, data):
    method = data.get('Method')
    params_dict = data.get('Params')
    body_dict = data.get('Body')
    headers_dict = data.get('Headers')
    username = data.get('Auth')['username']
    password = data.get('Auth')['password']

    par = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if isinstance(url, str) and re.match(par, url):
        try:
            if method == 'GET':
                res = requests.get(url, params=(params_dict and body_dict),
                                   auth=(username, password) if username and password else None,
                                   headers=headers_dict)
                time = round(res.elapsed.total_seconds(), 2)
                status = res.status_code
                if res.headers.get('content-type')[:16] != 'application/json':
                    data.update({'Error': 'Data format not json'})
                    return data
                data.update({'Status': status})
                data.update({'Response': res.json()})
                data.update({'Time': time})
                return data
            elif method == 'POST':
                res = requests.post(url, auth=(username, password) if username and password else None,
                                    data=(params_dict or body_dict), headers=headers_dict)
                time = round(res.elapsed.total_seconds(), 2)
                status = res.status_code
                if res.headers.get('content-type')[:16] != 'application/json':
                    data.update({'Error': 'Data format not json'})
                    return data
                data.update({'Status': status})
                data.update({'Response': res.json()})
                data.update({'Time': time})
                return data
            elif method == 'PUT':
                res = requests.put(url, data=(params_dict or body_dict), headers=headers_dict,
                                   auth=(username, password) if username and password else None)
                time = round(res.elapsed.total_seconds(), 2)
                status = res.status_code
                if res.headers.get('content-type')[:16] != 'application/json':
                    data.update({'Error': 'Data format not json'})
                    return data
                data.update({'Status': status})
                data.update({'Response': res.json()})
                data.update({'Time': time})
                return data
            elif method == 'PATCH':
                res = requests.patch(url, data=(params_dict or body_dict), headers=headers_dict,
                                     auth=(username, password) if username and password else None)
                time = round(res.elapsed.total_seconds(), 2)
                status = res.status_code
                if res.headers.get('content-type')[:16] != 'application/json':
                    data.update({'Error': 'Data format not json'})
                    return data
                data.update({'Status': status})
                data.update({'Response': res.json()})
                data.update({'Time': time})
                return data
            elif method == 'DELETE':
                res = requests.delete(url, auth=(username, password) if username and password else None)
                time = round(res.elapsed.total_seconds(), 2)
                status = res.status_code

                data.update({'Status': status})
                data.update({'Time': time})
                return data
        except simplejson.errors.JSONDecodeError as e:
            data.update({'Error': e})
            return data
        except requests.exceptions.RequestException as e:
            data.update({'Error': e})
            return data
    else:
        data.update({'Error': 'Input correct URL'})
        return data
