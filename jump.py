#!/usr/bin/env python

import requests
import yaml
import json

from flask import Flask, request, redirect, session, url_for
from flask.json import jsonify
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World!'

def login():
    client_id = '78420c74-1fdf-4575-b43f-eb94c7d770bf'
    auth_base_url = 'https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize'
    login_url = 'https://auth.api.sonyentertainmentnetwork.com/login.do'
    redirect_uri = 'https://www.bungie.net/en/User/SignIn/Psnid'
    response_type = 'code'
    scope = ['psn:s2s']
    locale = 'en'

    with open('creds.yml') as fd:
        creds = yaml.load(fd)

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
        print "Error getting initial OAuth cookie from PSN"
        exit(1)

    r = session.post(login_url, data=login_params, allow_redirects=False)
    if 'JSESSIONID' not in r.cookies or 'authentication_error' in r.headers['location']:
        print "Error authenticating to PSN"
        exit(1)

    r = session.get(auth_base_url, params=auth_params, allow_redirects=False)
    if 'bungie.net' not in r.headers['location']:
        print "Error completing OAuth transaction for Bungie callback"
        exit(1)

    r = requests.get(r.headers['location'])
    print json.dumps(requests.utils.dict_from_cookiejar(r.cookies), indent=4, sort_keys=True)
if __name__ == '__main__':
    login()
    #app.run()
