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

import subprocess
import re

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
            operator = get_operator()
        except Exception as e:
            print(e)
            abort(500)
        
        token = {
            'email': user_email,
            'token': get_random_string(),
            'created_on': datetime.datetime.utcnow(), # to periodically remove unverified tokens
            'assigned_namespace': ndn.Name(app.config['NAME_PREFIX']).append(get_random_string()).toUri()
            }
        mongo.db.tokens.insert(token)

        msg = Message("[NDN Open mHealth Certification] Request confirmation",
                      sender = app.config['MAIL_FROM'],
                      recipients = [user_email],
                      body = render_template('token-email.txt', URL=app.config['URL'], **token),
                      html = render_template('token-email.html', URL=app.config['URL'], **token))
        mail.send(msg)
        return json.dumps({"status": 200, "assigned_namespace": token['assigned_namespace']})
        
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
            abort(403, "No such token for this email address")

        # if getting operator fails, don't process this get request
        try:
            operator = get_operator()
        except Exception as e:
            print(e)
            abort(500, str(e))

        # don't delete token for now, just give user a form to input stuff
               
        return render_template('request-form.html', URL=app.config['URL'],
                               email=user_email, token=user_token, assigned_namespace=token['assigned_namespace'])
                
    else: # 'POST'
        # Email and token (to authorize the request==validate email)
        user_email = request.form['email']
        user_token = request.form['token']
        user_fullname = request.form['full_name']
        
        token = mongo.db.tokens.find_one({'email':user_email, 'token':user_token})
        if (token == None):
            abort(403, "No such token for this email address")

        # Now, do basic validation of correctness of user input, save request in the database
        # and notify the operator

        # if getting operator fails, don't process this post request
        try:
            operator = get_operator()
        except Exception as e:
            print(e)
            abort(500, str(e))

        if user_fullname == "":
            abort(400, "User full name should not be empty")
        try:
            user_cert_request = base64.b64decode(request.form['cert_request'])
            user_cert_data = ndn.Data()
            user_cert_data.wireDecode(ndn.Blob(buffer(user_cert_request)))
        except:
            abort(400, "Malformed cert request")
            
        # check if the user supplied correct name for the certificate request
        if not ndn.Name(token['assigned_namespace']).match(user_cert_data.getName()):
            abort(400, "cert name does not match with assigned namespace")
            
        cert_name = extract_cert_name(user_cert_data.getName()).toUri()
        
        if (not app.config['AUTO_APPROVE']):
            # manual approval of request needed
        
            # remove any previous requests for the same certificate name
            mongo.db.requests.remove({'cert_name': cert_name})

            cert_request = {
                    'operator_id': str(operator['_id']),
                    'full_name': user_fullname,
                    'organization': operator['site_name'],
                    'email': user_email,
                
                    'cert_name': cert_name,
                    'cert_request': base64.b64encode(user_cert_request),
                    'created_on': datetime.datetime.utcnow(), # to periodically remove unverified tokens
                }
            mongo.db.requests.insert(cert_request)

            # OK. authorized, proceed to the next step
            mongo.db.tokens.remove(token)

            msg = Message("[NDN Open mHealth Certification] User certification request",
                          sender = app.config['MAIL_FROM'],
                          recipients = [operator['email']],
                          body = render_template('operator-notify-email.txt', URL=app.config['URL'],
                                                 operator_name=operator['name'],
                                                 **cert_request),
                          html = render_template('operator-notify-email.html', URL=app.config['URL'],
                                                 operator_name=operator['name'],
                                                 **cert_request))
            mail.send(msg)

            return json.dumps({"status": 200})
        else:
            # automatically approve any cert request
            try:
                mongo.db.tokens.remove(token)
                cert = issue_certificate(request.form)
                ret = process_submitted_cert(cert, user_email, user_fullname)
                ret_obj = json.loads(ret)
                if (ret_obj['status'] != 200):
                    abort(ret_obj['status'], ret_obj['message'])
                else:
                    return json.dumps({"status": 200})
            except Exception as e:
                print(e)
                abort(500, str(e))
            

#############################################################################################
# Certificate issue and publish methods, only used if auto approve is select
#############################################################################################

def issue_certificate(request):
    today = datetime.datetime.utcnow()

    not_before = (today - datetime.timedelta(days=1)  ).strftime('%Y%m%d%H%M%S')
    not_after  = (today + datetime.timedelta(days=365)).strftime('%Y%m%d%H%M%S')

    # TODO: read the randomized user namespace and modify the --cert-prefix field
    cmdline = ['ndnsec-certgen',
               '--not-before', not_before,
               '--not-after',  not_after,
               '--subject-name', sanitize(request['full_name']),

               '--signed-info', '%s %s' % ('1.2.840.113549.1.9.1', sanitize(request['email'])),
               
               '--sign-id', str(app.config['NAME_PREFIX']),
               '--cert-prefix', str(app.config['NAME_PREFIX']),
               '--request', '-'
               ]

    p = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    cert, err = p.communicate(request['cert_request'])
    if p.returncode != 0:
        raise RuntimeError("ndnsec-certgen error")
    return cert.rstrip()


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
    if (not 'data' in request.form):
        abort(400, 'Expected \'data\' (certificate data) in request form')
    if (not 'email' in request.form):
        abort(400, 'Expected \'email\' (requester email) in request form')
    if (not 'full_name' in request.form):
        abort(400, 'Expected \'full_name\' (requester full name) in request form')
        
    ret = process_submitted_cert(request.form['data'], request.form['email'], request.form['full_name'])
    ret_obj = json.loads(ret)
    if ret_obj['status'] != 200:
        abort(ret_obj['status'], ret_obj['message'])
    else:
        return ret

def process_submitted_cert(cert_data, email, user_fullname):
    data = ndn.Data()
    data.wireDecode(ndn.Blob(buffer(base64.b64decode(cert_data))))
    
    # @todo verify data packet
    # Additional operator verification needed? Operator key should be verified
    operator_prefix = extract_cert_name(data.getSignature().getKeyLocator().getKeyName())
    operator = mongo.db.operators.find_one({'site_prefix': operator_prefix.toUri()})
    if operator == None:
        return json.dumps({"status": 500, "message": "operator not found [%s]" % operator_prefix})

    # @todo verify timestamp

    if (not app.config['AUTO_APPROVE']):
        cert_name = extract_cert_name(data.getName())
        cert_request = mongo.db.requests.find_one({'cert_name': cert_name.toUri()})

        if cert_request == None:
            return json.dumps({"status": 403, "message": "No cert request entry"})
    
    if len(data.getContent()) == 0:
        # (no deny reason for now)
        # eventually, need to check data.type: if NACK, then content contains reason for denial
        #                                      if KEY, then content is the certificate

        msg = Message("[NDN Open mHealth Certification] Rejected certification",
                      sender = app.config['MAIL_FROM'],
                      recipients = [email],
                      body = render_template('cert-rejected-email.txt',
                                             URL=app.config['URL'], fullname=user_fullname),
                      html = render_template('cert-rejected-email.html',
                                             URL=app.config['URL'], fullname=user_fullname))
        mail.send(msg)

        if (not app.config['AUTO_APPROVE']):
            mongo.db.requests.remove(cert_request)

        return json.dumps({"status": 200, "message": "Certificate request denied"})
    else:
        # may want to store assigned_namespace here as well
        cert = {
            'name': data.getName().toUri(),
            'cert': cert_data,
            'operator': operator,
            'created_on': datetime.datetime.utcnow(),
            }
        mongo.db.certs.insert(cert)

        msg = Message("[NDN Open mHealth Certification] certificate issued",
                      sender = app.config['MAIL_FROM'],
                      recipients = [email],
                      body = render_template('cert-issued-email.txt',
                                             URL=app.config['URL'],
                                             quoted_cert_name=urllib.quote(cert['name'], ),
                                             cert_id=str(data.getName()[-3]),
                                             fullname=user_fullname),
                      html = render_template('cert-issued-email.html',
                                             URL=app.config['URL'],
                                             quoted_cert_name=urllib.quote(cert['name'], ''),
                                             cert_id=str(data.getName()[-3]),
                                             fullname=user_fullname))
        mail.send(msg)
        
        if (not app.config['AUTO_APPROVE']):
            mongo.db.requests.remove(cert_request)

        return json.dumps({"status": 200, "message": "OK. Certificate has been approved and notification sent to the requester"})

#############################################################################################
# Helpers
#############################################################################################

def sanitize(value):
    # Allow only a very limited set of characters as a value
    return re.sub(r'[^a-zA-Z0-9.,\-!@#$%&*()\\/<>{}[]\|:`~ ]', r'', value)

def get_random_string(length = 60):
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(length)])

def ndnify(dnsName):
    ndnName = ndn.Name()
    for component in reversed(dnsName.split(".")):
        ndnName = ndnName.append(str(component))
    return ndnName

# zhehao: old md5 of user email as user's publishing namespace; not used for now
def generate_user_name_from_email(email):
    m = hashlib.md5()
    m.update(email)
    return m.hexdigest()
    
def get_operator():
    operator = mongo.db.operators.find_one({'site_prefix': app.config['NAME_PREFIX']})
    if (operator == None):
        raise Exception("No matching operators found")
    else:
        return operator

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
