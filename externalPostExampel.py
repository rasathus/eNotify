#!/usr/bin/env python
from urllib import urlencode
from urllib2 import urlopen, Request

params = {  'username' : 'rpm_builds',
            'message' : 'Another externally posted message.'}
data = urlencode(params)
req = Request('http://10.97.154.41:5000/add_insecure_message', data)
response = urlopen(req)
print "Post response : %s " % response.read()