#!/usr/bin/env python
'''
GNU GENERAL PUBLIC LICENSE v3
Copyright (C) <2016> JOSE (J) MARCOS <jm4rcos@gmail.com>

This program  is free software:  you  can redistribute it and/or modify it under
the  terms  of the GNU General Public License  as published by the Free Software
Foundation, either version 3  of  the  License, or  (at your option)  any  later
version.

This program  is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY;  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

See  <http://www.gnu.org/licenses/>  for  more details of the GNU General Public
License.
'''

'''
    Description:

    wf_urlCat.py - URL categorization using Blue Coat WebFilter.

    In order to succeed with this python script you have to have
    access to a licensed Blue Coat SG proxys running WebFilter.
'''

import datetime
import re
import socket
import getpass
import urllib2
import ssl
import netaddr
from netaddr import IPAddress
from bs4 import BeautifulSoup

def proxy_get_login_info():

    global pwd_mgr
    global proxy_ip

    try:

        print '\n{:-<79}'.format('-')
        print '         **** Categorization script for Blue Coat proxies. ****\n\n' + \
              'WARNING: In order to use this script sucessfuly you have to have access to a\n' + \
              'Blue Coat proxy licensed for web filtering.\n\n' + \
              'The script will categorize URLs against all enabled categorization providers.\n\n' + \
              '1. Single URL categorization:\n' + \
              'Show categorization for given URL.\n\n' + \
              '2. URL file categorization:\n' + \
              'Show categorization for each URL inside the provided URL file. URLs in file \n' + \
              'must be one per line. \n\n' + \
              '3. URL crawl and categorize: \n' + \
              'Show categorization for given URL and related categories from URLs contained \n' + \
              'in given URL.'


        print '{:-<79}'.format('-'), '\n'

        ''' Grab login information.
        '''

        raw_pip = IPAddress(raw_input('Proxy ip address: '.ljust(25)))
        dev_ip = str(raw_pip)

        try:
            _ip = re.split('\.',re.match(r'^\d+\.\d+\.\d+\.\d+$',dev_ip).group(0))

        except:
            raise ValueError('[-] Err: Enter ip address in the format X.X.X.X. Try again!.')

        if _ip[0] == '0' or _ip[0] == '255':
            raise ValueError('[-] Err: {0} : Enter a valid ip address.'.format(dev_ip))

        proxy_ip = str(raw_pip.ipv4())

        proxy_u  = raw_input('Proxy user name: '.ljust(25))

        if len(proxy_u) == 0:
            raise ValueError('[-] Err: user name can not be blank. Try again!.')

        proxy_p  = getpass.getpass('User password (hiden): '.ljust(25))

        if len(proxy_p) == 0:
            raise ValueError('[-] Err: password can not be blank. Try again!.')

        ''' Create a db to user/password mapping. It will be used in auth
            requests. The 'uri' part of .add_password is composed by blue
            coat proxy ip addr and mgmt port 8082.
        '''
        pwd_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()

        ''' Adding URL, username and password to password manager.
        '''

        pwd_mgr.add_password(None, proxy_ip + ':8082', proxy_u, proxy_p)

    except ValueError, Err:
        print '\n', Err
        exit()

    except netaddr.core.AddrFormatError, Err:
        print '\n[-] Err:', Err
        exit()

    except KeyboardInterrupt, Err:
        print '\n[-] <KeyboardInterrupt>: User interrupted'
        exit()

    except EOFError, e:
        print '\n<KeyboardInterrupt>: User interrupted, done!'
        exit()

def get_proxy_info():

    try:
        ''' setting connection timeout
        '''
        timeout = 5
        socket.setdefaulttimeout(timeout)

        ''' Create the openner
        '''
        open_url = urllib2.build_opener(urllib2.HTTPBasicAuthHandler(pwd_mgr))

        ''' Disabling SSL cert verification
        '''
        ssl._create_default_https_context = ssl._create_unverified_context

        print '\n[+] connecting ... ({}s timeout)'.format(timeout)

        get_p_version =  open_url.open('https://'+ proxy_ip + ':8082/SYSINFO/Version')
        _version = get_p_version.readlines()

        print '[+] connected and authenticated to', proxy_ip
        print '[+] getting proxy info and webfilter providers status ...', '\n'

        print '{:-<79}'.format('-')
        print 'Proxy information '
        print '{:-<79}'.format('-')

        for line in _version :
            if line.startswith('Version'):print line.strip('\n')
            if line.startswith('Release'):print line.strip('\n')
            if line.startswith('Serial'): print line.strip('\n'), '\n'

        check_Providers()

        print '{:-<79}'.format('-')
        print 'Categorization providers status '
        print '{:-<79}'.format('-')

        for k in providers_dict:
            print 'Provider: '.ljust(15), k, '({})'.format(providers_dict[k])

    except urllib2.URLError, e:
        print "[-]Err: {}".format(e.reason)
        exit()

    except KeyboardInterrupt, e:
        print '\n<KeyboardInterrupt>: User interrupted, done!'
        exit()

    except EOFError, e:
        print '\n<KeyboardInterrupt>: User interrupted, done!'
        exit()


def check_Providers():

    global providers_dict

    providers_dict = {}

    open_url = urllib2.build_opener(urllib2.HTTPBasicAuthHandler(pwd_mgr))
    get_wf_status =  open_url.open('https://'+ proxy_ip + ':8082/ContentFilter/Status')

    _status = get_wf_status.readlines()

    for item in _status:
        if item.startswith('Provider'):
            provider = item.split(':')[1].lstrip().strip('\n')
            continue
        if item.startswith('Status'):
            p_status = item.split(':')[1].lstrip().strip('\n')
            continue


        providers_dict[provider] = p_status

    return providers_dict


def get_url_cat(url):

    global categs

    try:
        timeout = 5
        socket.setdefaulttimeout(timeout)
        open_url = urllib2.build_opener(urllib2.HTTPBasicAuthHandler(pwd_mgr))
        ssl._create_default_https_context = ssl._create_unverified_context

        get_url_cat =  open_url.open('https://'+ proxy_ip + ':8082/ContentFilter/TestUrl/' + url)

        urlcat = get_url_cat.read()
        categs = urlcat.strip('\n').split('\n  ')
        categs[0] = categs[0].lstrip()

        return categs

    except urllib2.URLError, e:
        print "[-]Err: {}".format(e.reason)

    except KeyboardInterrupt, e:
        print '\n<KeyboardInterrupt>: User interrupted, done!'
        exit()


def get_url_cat_from_file(urlfile):

    ''' funcion returns a dictionary with links and related categories
    '''

    global url_dict

    try:
        with open(urlfile) as f:
            urls = f.readlines()

    except IOError, e:
        print e
        main()

    url_list = [ link.strip() for link in urls ]

    try:
        url_dict = {}

        timeout = 5
        socket.setdefaulttimeout(timeout)
        open_url = urllib2.build_opener(urllib2.HTTPBasicAuthHandler(pwd_mgr))
        ssl._create_default_https_context = ssl._create_unverified_context

        for link in url_list:
            get_url_cat =  open_url.open('https://'+ proxy_ip + ':8082/ContentFilter/TestUrl/' + link)
            urlcat = get_url_cat.read()
            categs = urlcat.strip('\n').split('\n  ')
            categs[0] = categs[0].lstrip()

            url_dict[link] = categs

        return url_dict

    except urllib2.URLError, e:
        print "[-]Err: {}".format(e.reason)


    except KeyboardInterrupt, e:
        print '\n<KeyboardInterrupt>: User interrupted, done!'
        exit()

def url_crawler(url):

    global providers2categs

    url_list = []

    b_categs_list = []
    p_categs_list = []

    providers2categs = {}

    try:
        resp = urllib2.urlopen(url)
        soup = BeautifulSoup(resp, 'lxml', from_encoding=resp.info().getparam('charset'))

        for link in soup.find_all('a', href=True):
            if link['href'].startswith('http'):
                url_list.append(link['href'])

        for l in url_list:
            get_url_cat(l)

        # ''' Policy categories, based on 'categs' returned by function get_url_cat()
        # '''
            for item in categs:
                provider = item.split(':')[0]
                p_categs = item.split(':')[1].split(';')
                if provider in providers2categs:
                    for cat in p_categs:
                        if cat.lstrip() not in providers2categs[provider]:
                            providers2categs[provider].append(cat.lstrip(' '))

                else:
                    p_categs = [i.lstrip() for i in p_categs]
                    providers2categs[provider] = p_categs



        return providers2categs

    except urllib2.URLError, e:
        print "[-]Err: {}".format(e.reason)


''' -----------------------------
    main
    -----------------------------
'''

def main ():
    while True:

        print '\n{:-<79}'.format('-')
        print 'Categorization menu'
        print '{:-<79}'.format('-')
        print '1. Single URL categorization'
        print '2. URL file categorization'
        print '3. URL crawl and categorize'

        try:
            c = raw_input('=>: ')

            if c == '1':
                print '\n{:-<79}'.format('-')
                print 'Single URL categorization'
                print '{:-<79}'.format('-')
                url = raw_input('\nURL to check: ')

                get_url_cat(url)

                print  '\n', url, categs

            elif c == '2':
                print '\n{:-<79}'.format('-')
                print 'URL file categorization'
                print '{:-<79}'.format('-')
                urlfile = raw_input('\nEnter file name: ')

                if len(urlfile) == 0:
                    print "[-] filename can not be empty."
                    main()

                get_url_cat_from_file(urlfile)

                for l in url_dict:
                    print l, url_dict[l]

            elif c == '3':
                print '\n{:-<79}'.format('-')
                print 'URL to crawl and categorize. Must start with "http(s)://"'
                print '{:-<79}'.format('-')
                url2c = raw_input('\nEnter URL to crawl: ')
                if not url2c.startswith('http'):
                    print '[-] http(s):// ...please'
                    main()

                print '[*] It takes time, be patient!...'

                get_url_cat(url2c)

                print '\n{:-<79}'.format('-')
                print 'Categories for: ', url2c
                print '{:-<79}'.format('-')
                print categs, '\n'

                url_crawler(url2c)

                print '{:-<79}'.format('-')
                print 'Related categories '
                print '{:-<79}'.format('-')
                for k in providers2categs: print  k, providers2categs[k]

        except KeyboardInterrupt, e:
            print '\n<KeyboardInterrupt>: User interrupted, done!'
            exit()

        except EOFError, e:
            print '\n<KeyboardInterrupt>: User interrupted, done!'
            exit()

proxy_get_login_info()
get_proxy_info()
main()
