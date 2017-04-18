#!/usr/bin/env python

import requests
import urllib2
from BeautifulSoup import BeautifulSoup


sr_bc_url = "http://sitereview.bluecoat.com/rest/categorization"
payload = {'url':'uol.com.br'}
headers = {'Referer':'http://www.sitereview.bluecoat.com/siterevew.jsp'}
r = requests.post(sr_bc_url, data=payload, headers=headers)
cats = BeautifulSoup(r.json()['categorization'])

print r.json()['url']
for c in str(cats).split('and'):
    print BeautifulSoup(c).text

#print r.content
