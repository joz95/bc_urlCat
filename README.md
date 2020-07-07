# URL categorization

* wf_urlCat.py

```
$ ./wf_urlCat.py

-------------------------------------------------------------------------------
         **** Categorization script for Blue Coat proxies. ****

WARNING: In order to use this script sucessfuly you have to have access to a
Blue Coat proxy licensed for web filtering.

The script will categorize URLs against all enabled categorization providers.

1. Single URL categorization:
Show categorization for given URL.

2. URL file categorization:
Show categorization for each URL in file. URLs in file must be one per line.

3. URL crawl and categorize:
Show categorization for given URL and related categories from URLs contained
in given URL.
-------------------------------------------------------------------------------

Proxy ip address:        <proxy_ip_addr>                     
Proxy user name:         <uid>
User password (hidden):  <passwd>

[+] connecting ... (5s timeout)
[+] connected and authenticated to <proxy_ip_addr>
[+] getting proxy info and webfilter providers status ...

-------------------------------------------------------------------------------
Proxy information
-------------------------------------------------------------------------------
Version: <sw_version>
Release id: <rel_id>
Serial number is <proxy_serial_number>

-------------------------------------------------------------------------------
Categorization providers status
-------------------------------------------------------------------------------
Provider:       Blue Coat (Ready)
Provider:       Local (Ready)
Provider:       YouTube (Enabled)
Provider:       IWF (Ready)

-------------------------------------------------------------------------------
Categorization menu
-------------------------------------------------------------------------------
1. Single URL categorization
2. URL file categorization
3. URL crawl and categorize
=>:

```
