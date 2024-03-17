from flask import Flask, render_template, request, jsonify
import requests
import hashlib
import uuid

app = Flask(__name__)

def random_string(length):
    import random
    import string
    characters = string.ascii_lowercase + "0123456789"
    return ''.join(random.choice(characters) for _ in range(length))

def encode_sig(data):
    sorted_data = {k: data[k] for k in sorted(data)}
    data_str = ''.join(f"{key}={value}" for key, value in sorted_data.items())
    return hashlib.md5((data_str + '62f8ce9f74b12f84c123cc23437a4a32').encode()).hexdigest()

def convertCookie(session):
    cookie = ''
    for i in range(len(session)):
        cookie += session[i]['name'] + '=' + session[i]['value'] + '; '
    return cookie

def convertToken(token):
    response = requests.get(f'https://api.facebook.com/method/auth.getSessionforApp?format=json&access_token={token}&new_app_id=275254692598279')
    if 'error' in response.json():
        resolve()
    else:
        return response.json()['access_token']

def convert2FA(twofactor_code):
    try:
        return int(twofactor_code)
    except ValueError:
        return None

@app.route('/')
def index():
    return render_template('facebook_auth.html')

@app.route('/authenticate', methods=['POST'])
def authenticate():
    email = request.form['email']
    password = request.form['password']
    twofactor_code = request.form['twofactor_code']

    deviceID = str(uuid.uuid4())
    adid = str(uuid.uuid4())
    random_str = random_string(24)

    form = {
        'adid': adid,
        'email': email,
        'password': password,
        'format': 'json',
        'device_id': deviceID,
        'cpl': 'true',
        'family_device_id': deviceID,
        'locale': 'en_US',
        'client_country_code': 'US',
        'credentials_type': 'device_based_login_password',
        'generate_session_cookies': '1',
        'generate_analytics_claim': '1',
        'generate_machine_id': '1',
        'currently_logged_in_userid': '0',
        'irisSeqID': 1,
        'try_num': '1',
        'enroll_misauth': 'false',
        'meta_inf_fbmeta': 'NO_FILE',
        'source': 'login',
        'machine_id': random_str,
        'fb_api_req_friendly_name': 'authenticate',
        'fb_api_caller_class': 'com.facebook.account.login.protocol.Fb4aAuthHandler',
        'api_key': '882a8490361da98702bf97a021ddc14d',
        'access_token': '350685531728%7C62f8ce9f74b12f84c123cc23437a4a32',
    }

    form['sig'] = encode_sig(form)

    headers = {
        'content-type': 'application/x-www-form-urlencoded',
        'x-fb-friendly-name': form['fb_api_req_friendly_name'],
        'x-fb-http-engine': 'Liger',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    }

    url = 'https://b-graph.facebook.com/auth/login'

    try:
        response = requests.post(url, data=form, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'session_cookies' in data:
                data['cookies'] = convertCookie(data['session_cookies'])
            if 'access_token' in data:
                data['access_token'] = convertToken(data['access_token'])
            return jsonify({
                'status': True,
                'message': 'Retrieve information successfully!',
                'data': data
            })
        elif response.status_code == 401:
            return jsonify({
                'status': False,
                'message': response.json()['error']['message']
            })
        elif 'twofactor' in response.json() and response.json()['twofactor'] == '0':
            return jsonify({
                'status': False,
                'message': 'Please enter the 2-factor authentication code!'
            })
        else:
            twofactor_code = convert2FA(twofactor_code)
            if twofactor_code is not None:
                form['twofactor_code'] = twofactor_code
                form['encrypted_msisdn'] = ''
                form['userid'] = response.json()['error']['error_data']['uid']
                form['machine_id'] = response.json()['error']['error_data']['machine_id']
                form['first_factor'] = response.json()['error']['error_data']['login_first_factor']
                form['credentials_type'] = 'two_factor'
                form['sig'] = encode_sig(form)

                response = requests.post(url, data=form, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    if 'session_cookies' in data:
                        data['cookies'] = convertCookie(data['session_cookies'])
                    if 'access_token' in data:
                        data['access_token'] = convertToken(data['access_token'])
                    return jsonify({
                        'status': True,
                        'message': 'Retrieve information successfully!',
                        'data': data
                    })
                else:
                    return jsonify({
                        'status': False,
                        'message': response.json()
                    })
            else:
                return jsonify({
                    'status': False,
                    'message': 'Invalid 2-factor authentication code!'
                })
    except Exception as e:
        return jsonify({
            'status': False,
            'message': 'Please check your account and password again!'
        })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
