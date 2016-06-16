#!/usr/local/bin/python
# -*- coding: utf-8 -*-
import sys, getopt
sys.path.append('./apnsclient')
from OpenSSL import crypto
from apnsclient import *
import logging
logging.basicConfig()

class client:
    def __init__(self, cert='', key='', device_token='', message=''):
        if device_token is '' or message is '':
            raise Exception('invalid device_token or message')
        self.cert = cert
        self.key = key
        self.device_token = device_token
        self.message = message
    def send(self):
        # For feedback or non-intensive messaging
        #con = Session().new_connection("push_sandbox", cert_file="cert.pem", key_file="key.pem")
        #print 'cert:', self.cert
        #print 'key:', self.key
        con = Session().new_connection("push_sandbox", cert_string=self.cert, key_string=self.key)

        # Persistent connection for intensive messaging.
        # Keep reference to session instance in some class static/global variable,
        # otherwise it will be garbage collected and all connections will be closed.
        #session = Session()
        #con = session.get_connection("push_sandbox", cert_file="sandbox.pem")

        # New message to 3 devices. You app will show badge 10 over app's icon.
        message = Message(self.device_token, alert=self.message, badge=0)

        # Send the message.
        srv = APNs(con)
        try:
            res = srv.send(message)
        except:
            print "Can't connect to APNs, looks like network is down"
        else:
            # Check failures. Check codes in APNs reference docs.
            for token, reason in res.failed.items():
                code, errmsg = reason
                # according to APNs protocol the token reported here
                # is garbage (invalid or empty), stop using and remove it.
                print "Device failed: {0}, reason: {1}".format(token, errmsg)

            # Check failures not related to devices.
            for code, errmsg in res.errors:
                print "Error: {}".format(errmsg)

            # Check if there are tokens that can be retried
            if res.needs_retry():
                # repeat with retry_message or reschedule your task
                retry_message = res.retry()


if __name__ == "__main__":

    # May require "" for empty password depending on version
    p12 = crypto.load_pkcs12(file("cert.p12", 'rb').read(), 'YOUR_PASSWORD') 
    # PEM formatted private key
    key =  crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
    # PEM formatted certificate
    cert = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())

    if len(sys.argv) != 5:
        print 'sample.py -t <token> -m <message>'
    device_token = ''
    message = ''
    try:
        opts, args = getopt.getopt(sys.argv[1:],"ht:m:",[])
    except getopt.GetoptError:
      print 'sample.py -t <token> -m <message>'
      sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'sample.py -t <token> -m <message>'
            sys.exit()
        elif opt in ("-t"):
            device_token = arg
        elif opt in ("-m"):
            message = arg
    try:
        client = client(cert=cert, key=key, device_token=device_token, message=message)
    except Exception as e:
        print 'Exception:', str(e) 
    else:
        try:
            print 'message is sending...'
            client.send()
            print 'msg is sent'
        except Exception as e:
            print 'Exception:', str(e) 

