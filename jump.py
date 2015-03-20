#!/usr/bin/env python

import requests
import json

from flask import Flask, request, redirect, url_for
app = Flask(__name__)

bungalow = {
    'cookies': {},
    'headers': {
        'X-API-Key': 'a08ca144c892448d939e8b1ccc1a2f83'
    }
}

def pretty(data):
    return json.dumps(data, indent=4, sort_keys=True)

@app.route('/')
def manifest():
    if 'cookies' not in bungalow or not bungalow['cookies']:
        return redirect(url_for('login'))
    else:
        return pretty(bungalow['cookies'])

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

    if not login_params['j_username'] or not login_params['j_password']:
        return pretty({'response': 'Please submit both username and password'}), 401

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
    return pretty(r.json()), r.status_code

if __name__ == '__main__':
    app.run(debug=True)
