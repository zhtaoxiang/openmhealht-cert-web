#!/usr/bin/env python

# Copyright (c) 2014  Regents of the University of California
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# dependencies - flask, flask-pymongo
# pip install Flask, Flask-PyMongo

#html/rest
from flask import Flask, jsonify, abort, make_response, request, render_template
from flask.ext.pymongo import PyMongo
from flask.ext.mail import Mail, Message

# mail
import smtplib
from email.mime.text import MIMEText
import smtplib
import os
import string
import random
import datetime
import base64
import pyndn as ndn
import json
import urllib

# hashlib, md5
import hashlib

from bson import json_util

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')

# name of app is also name of mongodb "database"
app = Flask("ndncert", template_folder=tmpl_dir)
app.config.from_pyfile('%s/settings.py' % os.path.dirname(os.path.abspath(__file__)))
mongo = PyMongo(app)
mail = Mail(app)

app.mongo = mongo
app.mail = mail

from admin import admin
from cert import cert
app.register_blueprint(admin)
app.register_blueprint(cert)

#############################################################################################
# User-facing components
#############################################################################################

@app.route('/', methods = ['GET'])
@app.route('/tokens/request/', methods = ['GET', 'POST'])
def request_token():
    if request.method == 'GET':
        #################################################
        ###              Token request                ###
        #################################################
        return render_template('token-request-form.html', URL=app.config['URL'])

    else: # 'POST'
        #################################################
        ###        Token creation & emailing          ###
        #################################################
        user_email = request.form['email']
        
        try:
            # pre-validation
            params = get_operator_and_namespace(user_email)
        except Exception as e:
            print(e)
            abort(500)
        
        token = {
            'email': user_email,
            'token': generate_token(),
            'created_on': datetime.datetime.utcnow(), # to periodically remove unverified tokens
            }
        mongo.db.tokens.insert(token)

        msg = Message("[NDN Certification] Request confirmation",
                      sender = app.config['MAIL_FROM'],
                      recipients = [user_email],
                      body = render_template('token-email.txt', URL=app.config['URL'], **token),
                      html = render_template('token-email.html', URL=app.config['URL'], **token))
        mail.send(msg)
        return json.dumps({"status": 200})
        
@app.route('/help', methods = ['GET'])
def show_help():
    return render_template('how-it-works.html')

@app.route('/cert-requests/submit/', methods = ['GET', 'POST'])
def submit_request():
    if request.method == 'GET':
        # Email and token (to authorize the request==validate email)
        user_email = request.args.get('email')
        user_token = request.args.get('token')
        
        token = mongo.db.tokens.find_one({'email':user_email, 'token':user_token})
        if (token == None):
            abort(403)

        # infer parameters from email
        try:
            # pre-validation
            params = get_operator_and_namespace(user_email)
        except Exception as e:
            print(e)
            abort(500)

        # don't delete token for now, just give user a form to input stuff
        
        # Zhehao: I don't think this GET request should have a mobile interface
        #if flag == 'mobileApp':
        #    return json.dumps({"organization": params['operator']['site_name']})
        #else:
        
        return render_template('request-form.html', URL=app.config['URL'],
                               email=user_email, token=user_token, **params)
                
    else: # 'POST'
        # Email and token (to authorize the request==validate email)
        user_email = request.form['email']
        user_token = request.form['token']

        token = mongo.db.tokens.find_one({'email':user_email, 'token':user_token})
        if (token == None):
            abort(403)

        # Now, do basic validation of correctness of user input, save request in the database
        # and notify the operator
        user_fullname = request.form['full-name']
        
        # zhehao: we don't do optional fields any more
        #optional parameters
        #user_homeurl = request.form['homeurl'] if 'homeurl'   in request.form else ""
        #user_group   = request.form['group']   if 'group'   in request.form else ""
        #user_advisor = request.form['advisor'] if 'advisor' in request.form else ""

        # infer parameters from email
        try:
            # pre-validation
            params = get_operator_and_namespace(user_email)
        except Exception as e:
            print(e)
            abort(500)

        if user_fullname == "":
            return json.dumps({"status": 400, "message": "User full name should not be empty"})
            
        try:
            user_cert_request = base64.b64decode(request.form['cert-request'])
            user_cert_data = ndn.Data()
            user_cert_data.wireDecode(ndn.Blob(buffer(user_cert_request)))
        except:
            return json.dumps({"status": 400, "message": "Malformed cert request"})
            
        # check if the user supplied correct name for the certificate request
        if not params['assigned_namespace'].match(user_cert_data.getName()):
            return json.dumps({"status": 400, "message": "cert name does not match with assigned namespace"})
            
        cert_name = extract_cert_name(user_cert_data.getName()).toUri()
        # remove any previous requests for the same certificate name
        mongo.db.requests.remove({'cert_name': cert_name})

        cert_request = {
                'operator_id': str(params['operator']['_id']),
                'fullname': user_fullname,
                'organization': params['operator']['site_name'],
                'email': user_email,
                
                'cert_name': cert_name,
                'cert_request': base64.b64encode(user_cert_request),
                'created_on': datetime.datetime.utcnow(), # to periodically remove unverified tokens
            }
        mongo.db.requests.insert(cert_request)

        # OK. authorized, proceed to the next step
        mongo.db.tokens.remove(token)

        msg = Message("[NDN Certification] User certification request",
                      sender = app.config['MAIL_FROM'],
                      recipients = [params['operator']['email']],
                      body = render_template('operator-notify-email.txt', URL=app.config['URL'],
                                             operator_name=params['operator']['name'],
                                             **cert_request),
                      html = render_template('operator-notify-email.html', URL=app.config['URL'],
                                             operator_name=params['operator']['name'],
                                             **cert_request))
        mail.send(msg)

        return json.dumps({"status": 200})
        
#############################################################################################
# Operator-facing components
#############################################################################################

@app.route('/cert-requests/get/', methods = ['POST'])
def get_candidates():
    commandInterestName = ndn.Name()
    commandInterestName.wireDecode(
        ndn.Blob(buffer(base64.b64decode(request.form['commandInterest']))))

    timestamp  = commandInterestName[-3]
    
    keyLocator = ndn.Name()
    keyLocator.wireDecode(commandInterestName[-2].getValue())
    signature  = commandInterestName[-1]
        
    operator = mongo.db.operators.find_one({'site_prefix': keyLocator.toUri()})
    if operator == None:
        abort(403)

    # @todo Command Interest verification

    requests = mongo.db.requests.find({'operator_id': str(operator['_id'])})
    output = []
    for req in requests:
        output.append(req)

    # return json.dumps (output)
    return json.dumps(output, default=json_util.default)

@app.route('/cert/submit/', methods = ['POST'])
def submit_certificate():
    data = ndn.Data()
    data.wireDecode(ndn.Blob(buffer(base64.b64decode(request.form['data']))))

    operator_prefix = extract_cert_name(data.getSignature().getKeyLocator().getKeyName())

    operator = mongo.db.operators.find_one({'site_prefix': operator_prefix.toUri()})
    if operator == None:
        return make_response('operator not found [%s]' % operator_prefix, 403)
        abort(403)

    # @todo verify data packet
    # @todo verify timestamp

    cert_name = extract_cert_name(data.getName())
    cert_request = mongo.db.requests.find_one({'cert_name': cert_name.toUri()})

    if cert_request == None:
        print("No cert request entry")
        abort(403)

    # infer parameters from email
    try:
        # pre-validation
        params = get_operator_and_namespace(cert_request['email'])
    except Exception as e:
        print(e)
        abort(403)
        return

    if len(data.getContent()) == 0:
        # (no deny reason for now)
        # eventually, need to check data.type: if NACK, then content contains reason for denial
        #                                      if KEY, then content is the certificate

        msg = Message("[NDN Certification] Rejected certification",
                      sender = app.config['MAIL_FROM'],
                      recipients = [cert_request['email']],
                      body = render_template('cert-rejected-email.txt',
                                             URL=app.config['URL'], **cert_request),
                      html = render_template('cert-rejected-email.html',
                                             URL=app.config['URL'], **cert_request))
        mail.send(msg)

        mongo.db.requests.remove(cert_request)

        return "OK. Certificate has been denied"
    else:
        cert = {
            'name': data.getName().toUri(),
            'cert': request.form['data'],
            'operator': operator,
            'created_on': datetime.datetime.utcnow(), # to periodically remove unverified tokens
            }
        mongo.db.certs.insert(cert)

        msg = Message("[NDN Certification] NDN certificate issued",
                      sender = app.config['MAIL_FROM'],
                      recipients = [cert_request['email']],
                      body = render_template('cert-issued-email.txt',
                                             URL=app.config['URL'],
                                             assigned_namespace=params['assigned_namespace'],
                                             quoted_cert_name=urllib.quote(cert['name'], ''),
                                             cert_id=str(data.getName()[-3]),
                                             **cert_request),
                      html = render_template('cert-issued-email.html',
                                             URL=app.config['URL'],
                                             assigned_namespace=params['assigned_namespace'],
                                             quoted_cert_name=urllib.quote(cert['name'], ''),
                                             cert_id=str(data.getName()[-3]),
                                             **cert_request))
        mail.send(msg)

        mongo.db.requests.remove(cert_request)

        return "OK. Certificate has been approved and notification sent to the requester"

#############################################################################################
# Helpers
#############################################################################################

def generate_token():
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(60)])

def ndnify(dnsName):
    ndnName = ndn.Name()
    for component in reversed(dnsName.split(".")):
        ndnName = ndnName.append(str(component))
    return ndnName

# zhehao: mhealth namespace claiming logic
def generate_user_name_from_email(email):
    m = hashlib.md5()
    m.update(email)
    return m.hexdigest()

def get_operator_and_namespace(email):
    operator = mongo.db.operators.find_one({'site_prefix': '/zhehao'})
    if (operator == None):
        raise Exception("No matching operators found")
    else:
        user = generate_user_name_from_email(email)
        assigned_namespace = ndn.Name('/zhehao')
        assigned_namespace.append(str(user))
    return {'operator':operator, 'user':user,
            'assigned_namespace':assigned_namespace}

# TODO: zhehao: replace this method with mHealth namespace claiming logic
def get_operator_for_email(email):
    # very basic pre-validation
    user, domain = email.split('@', 2)
    
    # zhehao: for the local test, all requests go to the operator zhehao
    #operator = mongo.db.operators.find_one({'site_emails': {'$in':[ domain ]}})
    operator = mongo.db.operators.find_one({'site_prefix': '/zhehao'})
    
    if (operator == None):
        operator = mongo.db.operators.find_one({'site_emails': {'$in':[ 'guest' ]}})

        if (operator == None):
            raise Exception("Unknown site for domain [%s]" % domain)

        # Special handling for guests
        ndn_domain = ndn.Name("/ndn/guest")
        assigned_namespace = ndn.Name('/ndn/guest')
        assigned_namespace.append(str(email))
    else:
        if domain == "operators.named-data.net":
            ndn_domain = ndn.Name(str(user))
            assigned_namespace = ndn.Name(str(user))
        else:
            ndn_domain = ndnify(domain)
            # zhehao: for local test site, the root cert name begins with /zhehao, we use it to replace /ndn temporarily
            assigned_namespace = ndn.Name('/zhehao')
            assigned_namespace \
                .append(ndn_domain) \
                .append(str(user))

    # return various things
    return {'operator':operator, 'user':user, 'domain':domain,
            'ndn_domain':ndn_domain, 'assigned_namespace':assigned_namespace}

def extract_cert_name(name):
    # remove two (or 3 in case of rejection) last components and remove "KEY" keyword at any position
    newname = ndn.Name()
    last = -2
    if name[-1] == 'REVOKED':
        last = -3
    for component in name[:last]:
        if str(component) != 'KEY':
            newname.append(component)
    return newname

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0')
