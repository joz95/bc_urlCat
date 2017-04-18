#!/usr/bin/env python
#
# title           :wf_urlCat.py
# author          :jm4rcos
# date            :
# version         :0.0
# notes           :initial version
# python_version  :2.7.6

'''
    Description:

    wf_urlCat.py - URL categorization using Blue Coat WebFilter.

    In order to succeed with this python script you have to have
    access to a licensed Blue Coat SG proxys running WebFilter.
'''


import getpass
import urllib2
import ssl          #imported to handle error in autentication, weird so far!


def proxy_connect():
    try:
        ''' Create a context to not verify SSL certificate
        '''
        cert_context = ssl._create_unverified_context()
        print '\n[+] Connecting ...'
        get_p_version =  urllib2.Request('https://'+ proxy_ip + ':8082/SYSINFO/Version')
        gpv_resp = urllib2.urlopen(get_p_version,context=cert_context,data=None,timeout=2)
        _version = gpv_resp.read().split('\r\n')
        print '[+] Connected and authenticated to', proxy_ip, '\n'
        print '++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'
        print '[+] Proxy ', proxy_ip
        for line in _version :
            if line.startswith('<'):continue
            if line.startswith('The Pr'):
                print '[+] L'+line[27:]
                continue
            print '[+]', line
        print '++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n'
    except urllib2.URLError :
        print '\n[-] <error>: Operation timed out.'
        print 'Blue Coat proxy is not reachable or port 8082 not open/replying.\n'
        exit()
    except ssl.SSLError :
        print '\n[-] <error>: Operation timed out.'
        print 'Admin username or password is wrong, please try again!\n'
        exit()

def check_WebFilter():
    count1 = 0
    count2 = 0
    wf_enabled = 'NOK'
    get_p_version =  urllib2.Request('https://'+ proxy_ip + ':8082/ContentFilter/Status')
    gpv_resp = urllib2.urlopen(get_p_version,data=None,timeout=2)

    _version = gpv_resp.read()
    _version = _version.split('\n')

    for line in _version:
        if line.startswith('Provider:'):
            line = line.split()
            if line[1] == 'Blue':
                print "[+] Webfilter enabled ...\n"
                wf_enabled = 'OK'
            else:
                continue

    if wf_enabled == 'NOK':
        print '[-] WebFilter is disbled.\nMakes no sense to categorize URLs against this proxy. Try another one!\n'
        exit()
    else:
        print '++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'
        print 'WebFilter status: '
        for line in _version:

            if count1 == 1 and line.startswith('  Blue Coat download at:'):
                print 'Previous download: ', line[2:]

            if count1 == 0 and line.startswith('  Blue Coat download at:'):
                print 'Download log: ', line[2:]
                count1 = count1 + 1

            if count2 == 1 and line.startswith('  Differential'):
                print 'Previous download: ', line[2:]

            if count2 == 0 and line.startswith('  Differential'):
                count2 = count2 + 1
                continue

            if line.startswith('  Database date:'): print 'Previous download: ', line[2:]

            if line.startswith('  Database expires:'): print 'Previous download: ', line[2:]
        print '++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n'


try:
    print '\n'
    # ''' Grab login information.
    # '''
    proxy_ip = raw_input('Proxy ip address: ')
    proxy_u  = raw_input('Proxy Admin user name: ')
    proxy_p  = getpass.getpass('Admin user password (hiden): ')

    '''
    Create a db to user/password mapping. It will be used in auth
    requests. The 'uri' part of .add_password is composed by blue coat proxy
    ip addr and mgmt port 8082.
    '''
    pwd_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
    pwd_mgr.add_password(None, proxy_ip+ ':8082', proxy_u, proxy_p)
    urllib2.install_opener(urllib2.build_opener(urllib2.HTTPBasicAuthHandler(pwd_mgr)))

    ''' Call function to connect to Blue Coat proxy, test authentication, grab
        some information and handle possible errors.
    '''
    proxy_connect()

    ''' Call function to check WebFilter state.
    '''
    check_WebFilter()

except KeyboardInterrupt:
    print '\n<KeyboardInterrupt>: User interrupted, done!'
    exit()


while True:

    try:
        urlList = []
        print '\nInput URLs ("q" to quit): '
        while True:
            url2cat = raw_input()

            if url2cat == 'q': exit()

            elif url2cat:
                urlList.append(url2cat)

            else:
                break

        for _url in urlList:
            url2catReq = urllib2.Request('https://' + proxy_ip + ':8082/ContentFilter/TestUrl/' + _url)
            cat = urllib2.urlopen(url2catReq)
            data = cat.read()
            print _url, ',',data.strip()
            #print '\n'

    except KeyboardInterrupt:
        print '\n<KeyboardInterrupt>: User interrupted, done!'
        exit()


# Download log:
  # Rebuilding existing database at: 2016/03/02 14:58:48 -0300
  # Database date:        Wed, 02 Mar 2016 15:02:01 UTC
  # Database expires:     Fri, 01 Apr 2016 15:02:01 UTC
  # Database version:     360620300
#
# Download log:
  # Database load in progress...
# Previous download:
  # Rebuilding existing database at: 2016/03/02 14:58:48 -0300
  # Database date:        Wed, 02 Mar 2016 15:02:01 UTC
  # Database expires:     Fri, 01 Apr 2016 15:02:01 UTC
  # Database version:     360620300
