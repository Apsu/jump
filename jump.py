#!/usr/bin/env python

import requests
import yaml

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

    creds = yaml.load('creds')

    auth_params = {
        'response_type': response_type,
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'locale': locale
    }

    login_params = {
        'j_username': creds.username,
        'j_password': creds.password
    }

    session = requests.Session()

    r = session.get(auth_base_url, params=auth_params, allow_redirects=False)
    #print r.url, r.headers, r.cookies

    r = session.post(login_url, data=login_params, allow_redirects=False)
    #print r.url, r.headers, r.cookies

    r = session.get(auth_base_url, params=auth_params, allow_redirects=False)
    #print r.url, r.headers, r.cookies

    r = requests.get(r.headers['location'])
    print r.cookies
if __name__ == '__main__':
    login()
    #app.run()
