#!/usr/bin/env python

import requests
import json

from flask import Flask, request, redirect, url_for
app = Flask(__name__)

bungalow = {
    'cookies': {},
    'headers': {},
    'gamerId': None,
    'memberId': None,
    'type': '2'      # XBL = 1; PSN = 2
}

def pretty(data):
    return json.dumps(data, indent=4, sort_keys=True)

@app.route('/')
def get_bungalow():
    if 'cookies' not in bungalow or not bungalow['cookies']:
        return redirect(url_for('login'))
    else:
        return pretty(bungalow)

@app.route('/login', methods=['POST'])
def login():
    client_id = '78420c74-1fdf-4575-b43f-eb94c7d770bf'
    auth_base_url = 'https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize'
    login_url = 'https://auth.api.sonyentertainmentnetwork.com/login.do'
    redirect_uri = 'https://www.bungie.net/en/User/SignIn/Psnid'
    response_type = 'code'
    scope = ['psn:s2s']
    locale = 'en'

    auth_params = {
        'response_type': response_type,
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'locale': locale
    }

    login_params = {
        'j_username': request.args.get('username'),
        'j_password': request.args.get('password')
    }

    bungalow['headers']['X-API-Key'] = request.args.get('api-key')

    if (not login_params['j_username']
        or not login_params['j_password']
        or not bungalow['headers']['X-API-Key']
        ):
        return pretty({'response': 'Please submit username, password, and api-key'}), 401

    psn = requests.Session()
    r = psn.get(auth_base_url, params=auth_params, allow_redirects=False)
    if 'JSESSIONID' not in r.cookies:
        return pretty({'response': 'Error getting initial OAuth cookie from PSN'}), 403

    r = psn.post(login_url, data=login_params, allow_redirects=False)
    if 'JSESSIONID' not in r.cookies or 'authentication_error' in r.headers['location']:
        return pretty({'response': 'Error authenticating to PSN'}), 401

    r = psn.get(auth_base_url, params=auth_params, allow_redirects=False)
    if 'bungie.net' not in r.headers['location']:
        return pretty({'response': 'Error completing OAuth transaction for Bungie callback'}), 403

    r = requests.get(r.headers['location'])
    if r.status_code != 200:
        return pretty({'response': 'Error obtaining API cookies from Bungie'}), 403

    bungalow['cookies'] = requests.utils.dict_from_cookiejar(r.cookies)
    bungalow['headers']['x-csrf'] = bungalow['cookies']['bungled']
    return pretty({'response': 'Success'})

@app.route('/user')
def get_user():
    r = requests.get(
        'http://www.bungie.net/platform/User/GetBungieNetUser/',
        headers=bungalow['headers'],
        cookies=bungalow['cookies']
    )
    bungalow['gamerId'] = r.json()['Response']['psnId']
    return pretty(r.json()), r.status_code

@app.route('/manifest')
def get_manifest():
    r = requests.get(
        'http://www.bungie.net/platform/Destiny/Manifest',
        headers=bungalow['headers'],
        cookies=bungalow['cookies']
    )
    return pretty(r.json()), r.status_code

@app.route('/user/characters')
def get_characters():
    r = requests.get(
        'http://www.bungie.net/platform/Destiny/SearchDestinyPlayer/' +
        bungalow['type'] + '/' +
        bungalow['gamerId'] + '/',
        headers=bungalow['headers'],
        cookies=bungalow['cookies']
    )
    if not 'Response' in r.json():
        return r.text, 404

    bungalow['memberId'] = r.json()['Response'][0]['membershipId']
    r = requests.get(
        'http://www.bungie.net/platform/Destiny/TigerPSN/Account/' +
        bungalow['memberId'] + '/',
        headers=bungalow['headers'],
        cookies=bungalow['cookies']
    )
    if not 'Response' in r.json():
        return r.text, 404
    else:
        return pretty(r.json()), r.status_code

if __name__ == '__main__':
    app.run(debug=True)
