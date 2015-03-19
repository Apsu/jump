#!/usr/bin/env python

import requests
import json

from flask import Flask, request
app = Flask(__name__)

@app.route('/')
def manifest():
    return 'Manifesto!'

@app.route('/login', methods=['POST'])
def login():
    creds = {
        'username': request.args.get('username'),
        'password': request.args.get('password')
    }

    if not creds['username'] or not creds['password']:
        return 'Please submit both username and password', 401

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
        'j_username': creds['username'],
        'j_password': creds['password']
    }

    session = requests.Session()
    r = session.get(auth_base_url, params=auth_params, allow_redirects=False)
    if 'JSESSIONID' not in r.cookies:
        return "Error getting initial OAuth cookie from PSN", 403

    r = session.post(login_url, data=login_params, allow_redirects=False)
    if 'JSESSIONID' not in r.cookies or 'authentication_error' in r.headers['location']:
        return "Error authenticating to PSN", 401

    r = session.get(auth_base_url, params=auth_params, allow_redirects=False)
    if 'bungie.net' not in r.headers['location']:
        return "Error completing OAuth transaction for Bungie callback", 403

    r = requests.get(r.headers['location'])
    if r.status_code == 200:
        return json.dumps(requests.utils.dict_from_cookiejar(r.cookies), indent=4, sort_keys=True)
    else:
        return "Error obtaining API cookies from Bungie", 403

if __name__ == '__main__':
    app.run()
