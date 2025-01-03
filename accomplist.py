#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
==============================================================================================
 accomplist.py: v3.04-20241205-1 Copyright (C) 2018-2024 Chris Buijs <cbuijs@chrisbuijs.com>
==============================================================================================

Blocklist (Black/Whitelist) compiler/optimizer.

TODO:

- !!! Better Documentation / Remarks / Comments
- Fix unwhiting

==============================================================================================
'''

## Modules

# Make sure modules can be found
import sys
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# Standard/Included modules
import os, os.path, time, dbm, shelve
from copy import deepcopy

# Use requests module for downloading lists
import requests

# Use module regex instead of re, much faster less bugs
import regex

# Use module pytricia to find ip's in CIDR's dicts fast
import pytricia

# Use IPSet from IPy to aggregate
from IPy import IP, IPSet
import netaddr

# Use unicode-data to normalize inputs
#import unicodedata
import idna, codecs
sys.stdout = codecs.getwriter('utf8')(sys.stdout)
sys.stderr = codecs.getwriter('utf8')(sys.stderr)

# Use pubblic-suffix
from publicsuffix2 import PublicSuffixList
psl = PublicSuffixList()

# Speedup DNS
import socket
from socket import _socket
dnscache = dict()

##########################################################################################

## Variables/Dictionaries/Etc ...

# Sources file to configure which lists to use
norestriction = False
if len(sys.argv) > 2:
    sources = str(sys.argv[1])
    sourcename = sources.split('/')[-1].replace('.sources', '').upper()
    outputdir = str(sys.argv[2]).rstrip('/')
    workdir = outputdir + '/work'
    if len(sys.argv) > 3:
        print('NO RESTRICTION')
        norestriction = True

else:
    sources = '/opt/accomplist/standard.sources'
    sourcename = 'STANDARD'
    outputdir = '/opt/accomplist/standard'
    workdir = '/opt/accomplist/standard/work'

# IPASN
asnip = dict()
ipasn4 = pytricia.PyTricia(32)
ipasn6 = pytricia.PyTricia(128)
ipasnfile = '/opt/ipasn/ipasn-all.dat'
#ipasnfile = False
ipasnoutfile = '/opt/accomplist/ipasn-all-cidr-aggregated.dat.out'
ipasnfilecache = '/opt/accomplist/ipasn.cache'
ipasnlargest4 = 32
ipasnlargest6 = 128

# Lists
blacklist = dict() # Domains blacklist
whitelist = dict() # Domains whitelist
cblacklist4 = pytricia.PyTricia(32) # IPv4 blacklist
cwhitelist4 = pytricia.PyTricia(32) # IPv4 whitelist
cblacklist6 = pytricia.PyTricia(128) # IPv6 blacklist
cwhitelist6 = pytricia.PyTricia(128) # IPv6 whitelist
rblacklist = dict() # Regex blacklist (maybe replace with set()?)
rwhitelist = dict() # Regex whitelist (maybe replace with set()?)
excludelist = dict() # Domain excludelist
asnwhitelist = dict() # ASN Whitelist
asnblacklist = dict() # ASN Blacklist
safeblacklist = dict() # Safe blacklist anything is this list will not be touched
safewhitelist = dict() # Safe whitelist anything is this list will not be touched
safeunwhitelist = dict() # Keep unwhitelisted entries safe
topdoms = dict() # Domains only TOP-N
invalidskipped = dict()

# ReplaceA
#replacefile = False
#replacefile = '/opt/accomplist/accomplist.replace'
#replacelist = dict()

# Work caches
dom_cache = dict()

# Save
blacksave = outputdir + '/black.list'
whitesave = outputdir + '/white.list'
genericblacksave = outputdir + '/black.generic.list'
genericwhitesave = outputdir + '/white.generic.list'
tldsave = '/opt/accomplist/chris/valid-tlds.regex'

# regexlist
fileregex = dict()
fileregexlist = '/opt/accomplist/accomplist.listregexes'

# TLD file
tldlist = dict()
tldurl = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
tldfile = workdir + '/iana-tlds.list'
tldoutfile = '/opt/accomplist/chris/tld-iana.list'
adtldoutfile = '/opt/accomplist/chris/autodiscover.tld-iana.list'
tldfilerx = '/opt/accomplist/chris/tld-black.regex'
dnsmasqtldfile = '/opt/accomplist/chris/dnsmasq-tld.conf'

# TOP 1M
top1mfile = '/opt/accomplist/chris/top.list'
#top1mfile = False
#top1mlist = dict()
top1mlist = set()

# Strip
stripipexcludelist = [".2o7.net", ".in-addr.arpa", ".ip6.arpa"]
stripipexclude = tuple(stripipexcludelist)

# Unwhitelist domains, keep in mind this can remove whitelisted entries that are blocked by IP.
unwhitelist = True

# Any-TLD
anytld = False

# Allow RFC 2606 TLD's
rfc2606 = False

# Allow common intranet TLD's
intranet = False

# Allow block internet domains
notinternet = False

# Aggregate IP lists, can be slow on large list (more then 5000 entries)
aggregate = True # if false, only child subnets will be removed

# Creaete automatic white-safelist entries that are unwhitelisted
autowhitesafelist = True

# Default maximum age of downloaded lists, can be overruled in lists file
maxlistage = 43200 # In seconds

# Allow negate rules in regexes
negate = False
if norestriction:
    print('ALLOW NEGATE')
    negate = True

# Generate Reverse Domains from IPs
revdom = False

# Debug-level, the higher levels include the lower level informations (Default = 2)
debug = 2

## Regexes

# Default file regex
#defaultfregex = '^(?P<line>.*)$'
defaultfregex = '^(||(?P<default1>[^\^]+)\^|(0.0.0.0|127.0.0.1|::|::1)\s+(?P<default2>[a-z0-9\.\-]+i)|(?P<default3>[a-z0-9\.\-]+))$'

# Regex to match IPv4/IPv6 Addresses/Subnets (CIDR)
ip4regex = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(/(3[0-2]|[12]?[0-9]))*)'
ip6regex = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))*)'
ipregex4 = regex.compile('^' + ip4regex +'$', regex.I)
ipregex6 = regex.compile('^' + ip6regex +'$', regex.I)
ipregex = regex.compile('^(' + ip4regex + '|' + ip6regex +')$', regex.I)

# Regex to match regex-entries in lists
isregex = regex.compile('^[/\^].*[/\$]$')

# Regex for AS(N) number
asnregex = regex.compile('^AS[0-9]+$')

# Regex to match domains/hosts in lists
#isdomain = regex.compile('^[a-z0-9_\.\-]+$', regex.I) # According RFC plus underscore, works everywhere
isdomain = regex.compile('(?=^.{1,251}[a-z]$)(^((?!-)[a-z0-9_-]{0,62}[a-z0-9]\.)*(xn--[a-z0-9_-]{1,59}|[a-z]{2,63})$)', regex.I)
isdomaintld = regex.compile('^.*(\.\*)$', regex.I)


# Regex for excluded entries to fix issues
defaultexclude = '^(127\.0\.0\.1(/32)*|::1(/128)*|local(host|net[s]*))$'
exclude = regex.compile(defaultexclude, regex.I)

# Regex for www entries and the like
#stripfirstlabel = regex.compile('^(https*|ftps*|www[a-z]*)[0-9]*(-[a-z]+)*[0-9]*\..*$', regex.I)
stripfirstlabel = regex.compile('^([0-9am]|(http|ftp|www+)[sz]*[0-9]*)\..*$', regex.I)

# Protected TLD
tldprotect = regex.compile('^(com|edu|fr|gov|net|nl|org)$', regex.I)

# Punycode
ispuny = regex.compile('^.*xn--.*$', regex.I)

##########################################################################################

# Replace socket.getaddrinfo with caching version to speedup requests/urllib
def _getaddrinfo(host, port=53, family=0, type=0, proto=0, flags=0):
    #found = dom_find(host, dnscache, 'CACHE')
    #if found and found in dnscache:
    #    if dnscache.get(found, None) is None:
    #        return None

    if host in dnscache:
        return dnscache.get(host, None)

    try:
        result = _socket.getaddrinfo(host, port, family, type, proto, flags) or None
    except BaseException as err:
        result = None
        
    dnscache[host] = result

    return result

socket.getaddrinfo = _getaddrinfo


# Info messages
def log_info(msg):
    print(msg)
    sys.stdout.flush()
    return


# Error messages
def log_err(msg):
    print(msg)
    sys.stdout.flush()
    return


# Check against REGEX lists
def check_regex(name, bw):
    if (bw == 'black'):
        rlist = rblacklist
    else:
        rlist = rwhitelist

    for i in range(0, len(rlist)/3):
        checkregex = rlist[i, 1]
        if (debug >= 3): log_info('Checking ' + name + ' against regex \"' + rlist[i, 2] + '\"')
        if checkregex.search(name):
            return '\"' + rlist[i, 2] + '\" (' + rlist[i, 0] + ')'

    return False


# Add exclusions to lists
def add_exclusion(dlist, elist, slist, listname):
    before = len(dlist)

    log_info('\nAdding excluded entries to \"' + listname + '\" ...')

    for domain in dom_sort(elist.keys()):
        lid = elist[domain]
        if (debug >= 3): log_info('Adding excluded entry \"' + domain + '\" to \"' + listname + '\" (from ' + lid + ')')
        if domain in dlist:
            if dlist[domain].find(lid) == -1:
                dlist[domain] = dlist[domain] + ', ' + lid
        else:
            dlist[domain] = lid

        slist[domain] = lid

    after = len(dlist)
    count = after - before

    if (debug >= 2): log_info('Added ' + str(count) + ' new exclusion entries to \"' + listname + '\", went from ' + str(before) + ' to ' + str(after))

    return dlist


# Read file/list
def read_lists(lid, name, regexlist, iplist4, iplist6, domainlist, asnlist, safelist, safewlist, force, bw, getasn, maxnum, topcheck, wwwstrip, notld, rdom):

    orgid = lid

    addtolist = dict()

    seen = set()

    if (len(name) > 0):
        try:
            with open(name, 'r') as f:
                log_info('Reading ' + bw + '-file/list \"' + name + '\" (' + lid + ')')
                orgregexcount = (len(regexlist)/3-1)+1
                regexcount = orgregexcount
                ipcount = 0
                domaincount = 0
                asncount = 0
                skipped = 0
                topskipped = 0
                total = 0

                for line in f:
                    entry = line.split('#')[0].strip().replace('\r', '')
                    if len(entry) > 0 and (not entry.startswith('#')):
                        lid = orgid
                        elements = entry.split('\t')
                        if len(elements) > 1:
                            entry = elements[0]
                            if elements[1]:
                                #lid = elements[1]
                                comment = elements[1]

                        safed = False
                        if (safelist != False) and entry.endswith('!'):
                            entry = entry.rstrip('!')
                            safed = True

                        unwhite = False
                        if (not safed) and (unwhitelist != False) and entry.endswith('&'):
                            entry = entry.rstrip('&')
                            unwhite = True

                        total += 1

                        if entry.upper() not in seen: # Unduplicate
                            seen.add(entry.upper())

                            #if replacelist:
                            #    for rx in replacelist:
                            #        if (regex.match(rx, entry, regex.I)):
                            #            lid = 'Replaced ' + entry + ' ' + lid
                            #            newentry = regex.sub(rx, replacelist[rx], entry, regex.I)
                            #            if (debug >=3): log_info(name + ': Replaced \"' + entry + '\" with \"' + newentry + '\"')
                            #            entry = newentry
                            #            break

                            # It is an Regex
                            if (isregex.match(entry)): # and (entry.upper() not in seen):
                                cleanregex = entry.strip('/')
                                if negate is False and cleanregex.find('(?!') > 0:
                                    if (debug >= 3): log_info('INFO: Ignoring/Skipping NEGATE line/regex \"' + entry + '\"')
                                    skipped += 1

                                else:
                                    if cleanregex.find('(?!') > 0:
                                        if (debug >= 3): log_info('INFO: Using NEGATE line/regex \"' + entry + '\"')

                                    try:
                                        regexlist[regexcount, 0] = str(lid)
                                        regexlist[regexcount, 1] = regex.compile(cleanregex, regex.I)
                                        regexlist[regexcount, 2] = cleanregex
                                        regexcount += 1
                                    except BaseException as err:
                                        log_err(name + ': Skipped invalid line/regex \"' + entry + '\" - ' + str(err))
                                        skipped += 1

                                #seen.add(entry.upper())

                            # It is an ASN
                            elif asnregex.match(entry.upper()):
                                entry = entry.upper()
                                if entry in asnlist:
                                    if asnlist[entry].find(lid) == -1:
                                        asnlist[entry] = asnlist[entry] + ', ' + lid

                                    if (debug >=3): log_info('INFO: Skipped ASN entry\"' + entry + '\"')
                                    skipped += 1

                                else:
                                    asnlist[entry] = lid
                                    asncount += 1

                                if ipasnfile:
                                    asn = entry[2:]
                                    lst = asnip.get(asn, list())
                                    for ip in lst:
                                        if (debug >= 3): log_info('Added ' + ip + ' to \"' + lid + '\" from ASN ' + entry)
                                        if add_cidr(iplist4, iplist6, ip, lid + '-' + entry, False, force):
                                            ipcount += 1
                                        else: 
                                            if (debug >= 3): log_info('INFO: Skipped ASN entry\"' + entry + '\"')
                                            skipped += 1

                            # It is an IP
                            elif (ipregex.match(entry)):
                                asn = add_cidr(iplist4, iplist6, entry, lid, getasn, force)

                                if rdom:
                                    for reversedom in rev_ip(entry):
                                        if (debug >= 3): log_info('ADD-REV-IP: ' + entry + ' => ' + reversedom)
                                        domainlist[reversedom] = lid
                                        domaincount += 1
                                         

                                #if getasn and type(asn) == type(str()):
                                if getasn and isinstance(asn, str):
                                    asn, cidr = regex.split('\s+', asn)[0:2]
                                    if asn and cidr:
                                        if ':' in cidr:
                                            iplist = iplist6
                                        else:
                                            iplist = iplist4

                                        if asn not in asnlist:
                                            log_info('ADD-ASN: Adding ASN \"' + asn + '\" for ' + entry)
                                            asnlist[asn] = lid
                                            asncount += 1

                                        if not iplist.has_key(cidr):
                                            if add_cidr(iplist4, iplist6, cidr, lid + '-' + asn, False, force):
                                                log_info('ADD-ASN: Adding ' + cidr + ' from ' + asn + ' for ' + entry)
                                                ipcount += 1

                                elif asn == False:
                                    if (debug >=3): log_info('INFO: Skipped IP entry\"' + entry + '\"')
                                    skipped += 1
                                else:
                                    ipcount += 1

                            elif tldlist and isdomaintld.match(entry):
                                for dom in tldlist:
                                    domain = entry.rstrip('.*').lower() + '.' + dom
                                    if (isdomain.match(domain)) and (notld is False):
                                        log_info(lid + ': Added TLD entry \"' + entry + '\" -> \"' + domain + '\"')
                                        domainlist[domain] = 'TLD-' + lid
                                        domaincount += 1
                                    else:
                                        log_info(lid + ': Skipped invalid line/TLD \"' + entry + '\"')
                                        skipped += 1


                            elif isdomain.match(entry.strip('.')):
                                # It is a domain
                                domain = entry.strip('.').lower()

                                # TLDs not allowed
                                if notld and domain.count('.') < 1:
                                    if (debug >= 2): log_info('INFO: TLD NOT ALLOWED: ' + domain)
                                    domain = False
                                    skipped += 1

                                elif rdom and (domain.strip('.').endswith('.ip-addr.arpa') or domain.strip('.').endswith('.ip6.arpa')):
                                    if (debug >= 2): log_info('INFO: REVERSE DOMAINS NOT ALLOWED: ' + domain)
                                    domain = False
                                    skipped += 1

                                # Strip common start-labels if appropiate
                                elif force:
                                    if (debug >= 3): log_info('INFO: NO-STRIP: \"' + domain + '\"')
                                    forcestrip = False

                                elif wwwstrip and bw == 'black':
                                    wwwcount = 0
                                    newdomain = False
                                    stripinfo = "UNKNOWN"
                                    forcestrip = False

                                    # Common start labels like "www" etc
                                    domain2 = domain
                                    newdomain2 = False
                                    while stripfirstlabel.match(domain2) and regex.search('^' + ip4regex, domain2) is None and domain2.count('.') > 1:
                                        wwwcount += 1
                                        label = domain2.split('.')[0]
                                        newdomain2 = '.'.join(domain2.split('.')[1:])
                                        if (debug >= 3): log_info('INFO: Potential General Prefix: \"' + label + '\" (#' + str(wwwcount) + ') (' + domain2 + ')')
                                        domain2 = newdomain2
                                        if label and domain2.count('.') > 0 and regex.search('^www+[sz]*[0-9]*$', label):
                                            if (debug >= 3): log_info('INFO: Forcing Strip WEB Prefix: \"' + label + '\" (#' + str(wwwcount) + ') (' + domain2 + ')')
                                            forcestrip = True

                                    if domain2 != domain:
                                        stripinfo = "FIRST-LABEL"
                                        newdomain = domain2


                                    # Domain starts with IPv4 address (with dot)
                                    if not newdomain:
                                        if not domain.endswith(stripipexclude) and regex.search('^' + ip4regex + '\.', domain):
                                            domain2 = domain
                                            while regex.search('^' + ip4regex + '\.', domain2) and domain2.count('.') > 1:
                                                ipdomain = regex.sub('^' + ip4regex + '\.', '', domain2)
                                                if ipdomain != domain2:
                                                    ipaddr = regex.sub('^(?P<ip>' + ip4regex + ')\..*$', r'\g<ip>', domain2)
                                                    if (debug >= 3): log_info('INFO: Potential IPv4 prefix: \"' + ipaddr + '<.>' + ipdomain + '\" (' + domain2 + ')')
                                                    domain2 = ipdomain

                                            if domain2 != domain:
                                                stripinfo = "IPv4-WITH-DOT"
                                                newdomain = domain2
                                                forcestrip = True
                                                #if add_cidr(iplist4, iplist6, ipaddr, lid + '-' + domain, False, force):
                                                #    log_info('ADD-IP-FROM-DOM: Adding ' + ipaddr + ' from ' + domain)
                                                #    ipcount += 1


                                    # Domain starts with IPv4 address (without dot)
                                    if not newdomain:
                                        if not domain.endswith(stripipexclude) and regex.search('^' + ip4regex + '[^0-9\.\-].*$', domain):
                                            domain2 = domain
                                            while regex.search('^' + ip4regex + '[^0-9\.\-].*$', domain2) and domain2.count('.') > 1:
                                                ipdomain = regex.sub('^' + ip4regex + '(?P<dom>[^0-9\.\-].*)$', r'\g<dom>', domain2)
                                                if ipdomain != domain2:
                                                    ipaddr = regex.sub('^(?P<ip>' + ip4regex + ')[^0-9\.\-].*$', r'\g<ip>', domain2)
                                                    if (debug >= 3): log_info('INFO: Potential WhiteSpace missing: \"' + ipaddr + '< >' + ipdomain + '\" (' + domain + ')')
                                                    domain2 = ipdomain

                                            if domain2 != domain and domain2.count('.') > 0:
                                                sld = psl.get_sld(domain2)
                                                if sld:
                                                    stripinfo = "IPv4-NO-DOT"
                                                    newdomain = domain2
                                                    forcestrip = True
                                                else:
                                                    if (debug >= 2): log_info('INFO: Strip-Protected: Domain \"' + domain + '\" starts with IPv4 but SLD\"' + domain2 + '\" does not exist!')
                                                    


                                    # Domain starts with IP-Prefix (with dot)
                                    if not newdomain:
                                        ipprefix = '(([0-9a-f]{4,4}\.){4,8}|([0-9a-f]{2,2}\.){6,6}|([0-9a-f]\.){4,32})'
                                        if not domain.endswith(stripipexclude) and regex.search('^' + ipprefix, domain):
                                            domain2 = domain
                                            while regex.search('^' + ipprefix, domain2) and domain2.count('.') > 2:
                                                ipdomain = regex.sub('^' + ipprefix, '', domain2)
                                                if ipdomain != domain2:
                                                    ipaddr = regex.sub('^(?P<ip>' + ipprefix + ').*$', r'\g<ip>', domain2)
                                                    if (debug >= 3): log_info('INFO: Potential IP-Prefix: \"' + ipaddr.rstrip('.') + '<.>' + ipdomain + '\" (' + domain2 + ')')
                                                    domain2 = ipdomain

                                            # Comment out below if Info-Only for False-Positive protection
                                            if domain2 != domain and domain2.count('.') > 0:
                                                stripinfo = "IP-WITH-DOT"
                                                newdomain = domain2
                                                forcestrip = True


                                    # Stripper
                                    if (domain and newdomain) and (not domain.endswith(stripipexclude)):
                                        if bw == 'black':
                                            if forcestrip is True or psl.get_sld(newdomain) != newdomain:
                                                if (debug >= 2): log_info('INFO: Stripped ' + bw + 'listed \"' + domain + '\" -> \"' + newdomain + '\" (' + stripinfo + ')')
                                                domain = newdomain
                                            else:
                                                if (debug >= 2): log_info('INFO: Strip-Protected ' + bw + 'listed SLD: \"' + domain + '\" (' + stripinfo + ')')
                                        else:
                                            if (debug >= 2): log_info('INFO: WhiteList Strip-Protected: \"' + domain + '\" (' + stripinfo + ')')


                                if domain:
                                    if tldlist and (not safed) and (not force):
                                        sld = psl.get_sld(domain)
                                        if sld:
                                            if sld == domain:
                                                if (debug >= 3): log_info('INFO: DOMAIN \"' + domain + '\" is a SLD (\"' + sld + '\")')
                                        else:
                                            if (debug >= 2): log_info('INFO: DOMAIN \"' + domain + '\" SLD does not exist')

                                        if domain:
                                            if domain.count('.') > 0:
                                                tld = domain.split('.')[-1]
                                            else:
                                                tld = domain

                                            if not tld in tldlist:
                                                if (debug >= 2):log_info('Skipped DOMAIN \"' + domain + '\", TLD (' + tld + ') does not exist')
                                                domain = False
                                                addtolist[tld] = 'Invalid-TLD-' + lid
                                                skipped += 1

                                    
                                    if domain and topcheck and top1mlist:
                                        if domain.count('.') < 1:
                                            log_info('Top: \"' + domain + '\" = TLD')
                                        else:
                                            istop1m = dom_find(domain, top1mlist, 'top1mlist')
                                            if istop1m:
                                                log_info('Top: \"' + domain + '\" -> \"' + istop1m + '\"')
                                            else:
                                                log_info('Skipped \"' + domain + '\" - Not in TOP list')
                                                addtolist[domain] = 'Not-TOP-' + lid
                                                domain = False
                                                skipped += 1
                                                topskipped += 1

                                    if domain:
                                        if bw == 'black' and tldprotect.match(domain):
                                            log_info('TLD PROTECTED: \"' + domain + '\"')
                                            domain = False
                                            skipped += 1
                                            topskipped += 1
                                        else:
                                            if unwhite:
                                                if (debug >= 3): log_info('Added \"' + domain + '\" to ' + 'safe-unwhite-list')
                                                safewlist[domain] = lid
                                                skipped += 1
    
                                            else:
                                                if safed:
                                                    if (debug >= 3): log_info('Added \"' + domain + '\" to ' + bw + '-safelist')
                                                    if domain in safelist:
                                                        if safelist[domain].find('Safelist-' + lid) == -1:
                                                            safelist[domain] = safelist[domain] + ', Safelist-' + lid
                                                    else:
                                                        safelist[domain] = 'Safelist-' + lid
    
                                                if domain in domainlist:
                                                    if domainlist[domain].find(lid) == -1:
                                                        domainlist[domain] = domainlist[domain] + ', ' + lid
    
                                                    skipped += 1

                                                else:
                                                    domainlist[domain] = lid
                                                    domaincount += 1

                            elif anytld and entry.strip('.').count('.') == 0:
                                log_info(lid + ': Invalid TLD (Added Anyway): \"' + entry + '\"')
                                domain = entry.strip('.').lower()
                                domainlist[domain] = lid
                                addtolist[domain] = 'Invalid-TLD-' + lid
                                domaincount += 1

                            else:
                                if (debug >= 3): log_info(lid + ': Skipped invalid line/syntax \"' + entry + '\"')
                                skipped += 1

                        else:
                            skipped += 1 # Duplicate

                    if maxnum and ipcount + domaincount >= maxnum:
                        if (debug >=2 ): log_info(lid + ': Reached maximum number of entries (' + str(maxnum) + ')')
                        break

                if (debug >= 2): log_info('Processed ' + bw + 'list ' + str(total) + ' entries and skipped ' + str(skipped) + ' (existing/invalid) ones from \"' + orgid + '\"')
                if topcheck and (debug >= 2): log_info('Skipped ' + str(topskipped) + ' non-top entries')
                         
                if (debug >= 1): log_info('Fetched ' + bw + 'list ' + str(regexcount-orgregexcount) + ' REGEXES, ' + str(ipcount) + ' CIDRs, ' + str(domaincount) + ' DOMAINS and ' + str(asncount) + ' ASNs from ' + bw + '-file/list \"' + name + '\"')
                if (debug >= 2): log_info('Total ' + bw + 'list ' + str(len(regexlist)/3) + ' REGEXES, ' + str(len(iplist4) + len(iplist6)) + ' CIDRs, ' + str(len(domainlist)) + ' DOMAINS and ' + str(len(asnlist)) + ' ASNs in ' + bw + '-list')

                return addtolist

        except BaseException as err:
            log_err('READ-LIST: Unable to open file \"' + name + '\" (' + orgid + ') - ' + str(err))
            pass

    return False


# Add CIDR to iplist
def add_cidr(iplist4, iplist6, entry, lid, getasn, force):
    cidr = expand_ip(entry)

    if ":" in cidr:
        ipv6 = True
        iplist = iplist6
    else:
        ipv6 = False
        iplist = iplist4


    if entry != cidr and debug >= 3:
        log_info(lid + ': Fixed CIDR from \"' + entry + '\" to \"' + cidr + '\"')

    bits = cidr.split('/')[1]

    # Safety against to large subnets blocking
    if (ipv6 is False and bits < 8) or (ipv6 is True and bits < 20):
        if force:
            log_info(lid + ': Skipped invalid line/ip-address \"' + cidr + '\" - too large, max allowed: ipv4=/8 and ipv6=/20')
            return False
        else:
            log_info(lid + ': Allowed/Forced invalid line/ip-address \"' + cidr + '\" - too large, max allowed: ipv4=/8 and ipv6=/20')


    if getasn == False:
        if iplist.has_key(cidr):
            if iplist[cidr].find(lid) == -1:
                oldid = iplist[cidr].split('(')[1].split(')')[0].strip()
                try:
                    iplist[cidr] = '\"' + cidr + '\" (' + str(oldid) + ', ' + str(lid) + ')'
                except BaseException as err:
                    log_info(lid + ': Skipped invalid line/ip-address \"' + entry + '\" - ' + str(err))
                    return False
        else:
            try:
                iplist[cidr] = '\"' + cidr + '\" (' + str(lid) + ')'
            except BaseException as err:
                log_info(lid + ': Skipped invalid line/ip-address \"' + entry + '\" - ' + str(err))
                return False

    else:
        prefix = False
        if ipv6:
            asn = ipasn6.get(cidr, False)
            if asn:
                prefix = ipasn6.get_key(cidr)
        else:
            asn = ipasn4.get(cidr, False)
            if asn:
                prefix = ipasn4.get_key(cidr)

        if asn and prefix:
            return str('AS' + asn + ' ' + prefix)
        else:
            return False

    return True


def top_check(name, listname, threshold):
    domlist = dom_sort(name.keys())

    if (threshold is not False) and top1mlist and len(domlist) > threshold:
        if (debug >= 2): log_info('\nTOP-Check \"' + listname + '\": Checking against TOP list (' + str(threshold) + ')')

        new = dict()
        for domain in domlist:
            istop1m = dom_find(domain, top1mlist, 'top1mlist')
            if (istop1m is False) and (domain.count('.') > 0):
                if (debug >= 2): log_info('\"' + listname + '\": Removed domain \"' + domain + '\" - Not in TOP list')
            else:
                if (debug >= 2): log_info('\"' + listname + '\": Keeping domain \"' + domain + '\" - In TOP list')
                new[domain] = name[domain]
                   
        before = len(name)
        after = len(new)
        count = after - before

        if (debug >= 2): log_info('\"' + listname + '\": Number of domains went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')
        return new

    return name


def make_top(domlst, name):
    if top1mlist:
        if (debug >= 2): log_info('\nMaking TOP-N ' + name + ' ...')
        newdomlst = dict()
        for domain in sorted(domlst.keys()):
          
            topdom = dom_find(domain, top1mlist, 'top1mlist')
            if topdom:
                if topdom == domain:
                   if (debug >= 3): log_info('TOP-N: \"' + domain + '\" is \"' + topdom + "\"")
                else:
                   if (debug >= 3): log_info('TOP-N: \"' + domain + '\" part of \"' + topdom + "\"")

                newdomlst[domain] = domlst[domain]

        if (debug >= 2): log_info('TOP-N ' + name + ' has ' + str(len(newdomlst)) + ' domains (Full is ' + str(len(domlst)) + ')')

        if len(newdomlst) > 0:
            return newdomlst

    return domlst


# Domain aggregator, removes subdomains if parent exists
#def optimize_domlists(name, listname):
#    if (debug >= 2): log_info('\nOptimizing doms from ' + listname)
#
#    # Remove all subdomains
#    parent = '.invalid'
#    undupped = set()
#    domlist = dom_sort(name.keys())
#    for domain in domlist:
#        if not domain.endswith(parent):
#                undupped.add(domain)
#                parent = '.' + domain.strip('.')
#                if (debug >= 3): log_info('\"' + listname + '\": keeping domain \"' + domain + '\", no parent')
#        else:
#            if (debug >= 3): log_info('\"' + listname + '\": Removed domain \"' + domain + '\" redundant by parent \"' + parent.strip('.') + '\"')
#
#    # New/Work dictionary
#    new = dict()
#
#    # Build new dictionary preserving id/category
#    for domain in undupped:
#        new[domain] = name[domain]
#
#    # Some counting/stats
#    before = len(name)
#    after = len(new)
#    count = after - before
#
#    if (debug >= 2): log_info('\"' + listname + '\": Number of domains went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')
#
#    return new
#
def optimize_domlists(name, listname):
    # It's good to have debug checks outside critical performance code or minimize its impact inside loops
    if debug >= 2:
        log_info('\nOptimizing doms from ' + listname)

    # Remove all subdomains
    parent = '.invalid'
    undupped = set()
    domlist = dom_sort(name.keys())  # Assuming dom_sort is necessary and optimized

    # Iterate through sorted domains
    for domain in domlist:
        # Improved string concatenation once
        parent_domain = '.' + domain.strip('.')
        if not domain.endswith(parent):
            undupped.add(domain)
            parent = parent_domain
            if debug >= 3:
                log_info('\"{}\": keeping domain \"{}\", no parent'.format(listname, domain))
        else:
            if debug >= 3:
                log_info('\"{}\": Removed domain \"{}\" redundant by parent \"{}\"'.format(listname, domain, parent.strip('.')))

    # Build new dictionary preserving id/category efficiently
    new = {domain: name[domain] for domain in undupped}

    # Counting stats without extra variables
    before = len(name)
    after = len(new)

    if debug >= 2:
        log_info('\"{}\": Number of domains went from {} to {} ({})'.format(listname, before, after, after - before))

    return new


# Unwhitelist IP's, if whitelist entry is not blacklisted, remove it.
def unwhite_ip(wlist, blist, listname, size):
    if not unwhitelist:
        return wlist

    if not blist:
        return wlist

    if (debug >= 2): log_info('\nUn-Whitelisting IPs from ' + listname)

    newwlist = pytricia.PyTricia(size)

    for ip in wlist:
        if ip in blist:
            newwlist[ip] = wlist[ip]
            if (debug >= 3): log_info('\"' + listname + '\": keeping IP \"' + ip + '\", is blacklisted')
        else:
            if (debug >= 3): log_info('\"' + listname + '\": Removed IP \"' + ip + '\", not blacklisted')
         
    before = len(wlist)
    after = len(newwlist)
    count = after - before

    if (debug >= 2): log_info('\"' + listname + '\": Number of IPs went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return newwlist


# Check if name exist in domain-list or is sub-domain in domain-list
def dom_find(name, dlist, listname):
    if name:
        testname = False
        for label in name.split('.')[::-1]:
            testname = label + '.' + testname if testname else label

            if testname in dlist:
                return testname

    return False


# Unwhitelist domains, if whitelist entry is not blacklisted, remove it.
def unwhite_domain(wlist, blist, force):
    if force is False and unwhitelist is False:
        return wlist

    if not blist:
        return wlist

    if (debug >= 2): log_info('\nUn-Whitelisting domains from whitelist')

    new = dict()

    for entry in dom_sort(wlist.keys()):
        if (ipregex.match(entry)):
            new[entry] = wlist[entry]
        else:
            testname = entry
            legit = False

            if dom_find(testname, safewhitelist, 'safewhitelist'):
                if (debug >= 3): log_info('Skipped unwhitelisting \"' + entry + '\" due to being safelisted')
            elif testname.count('.') > 0:
                found = dom_find(testname, blist, 'BlackDoms')
                if found:
                    legit = '\"' + found + '\" (' + blist[found] + ')'

            if legit is False:
                brx = check_regex(entry, 'black')
                if not brx:
                    if (debug >= 3): log_info('Removed redundant white-listed domain \"' + entry + '\" (No blacklist hits)')
                else:
                    if (debug >= 3): log_info('Keeping white-listed domain \"' + entry + '\", blacklisted by \"' + brx + '\"')
                    legit = brx

            if legit:
                new[entry] = wlist[entry] + ' - Blacklisted by ' + legit
            else:
                safeunwhitelist[entry] = 'Unwhitelist'

    before = len(wlist)
    after = len(new)
    count = before - after

    if (debug >= 2): log_info('Number of white-listed domains went from ' + str(before) + ' to ' + str(after) + ' (Unwhitelisted ' + str(count) + ')')

    return new


# Uncomplicate lists, removed whitelisted domains from blacklist
def uncomplicate_lists(whitelist, rwhitelist, blacklist, safelist):
    log_info('\nUncomplicating Domain black/whitelists')

    listw = dom_sort(whitelist.keys())
    listb = dom_sort(blacklist.keys() + safelist.keys())

    # Remove all 1-to-1/same whitelisted entries from blacklist
    # !!! We need logging on this !!!
    listb = dom_sort(list(set(listb).difference(listw)))

    # Create checklist for speed
    checklistb = '#'.join(listb) + '#'

    # loop through whitelist entries and find parented entries in blacklist to remove
    for domain in listw:
        if '.' + domain + '#' in checklistb:
            if (debug >= 3): log_info('Checking against \"' + domain + '\"')
            for found in filter(lambda x: x.endswith('.' + domain), listb):
                if dom_find(found, safelist, 'safelist') is False:
                   if (debug >= 3): log_info('Removed blacklist-entry \"' + found + '\" due to white-listed parent \"' + domain + '\"')
                   listb.remove(found)
                else:
                   if (debug >= 3): log_info('Preserved white-listed/safe-black-listed blacklist-entry \"' + found + '\" due to white-listed parent \"' + domain + '\"')

            checklistb = '#'.join(listb) + "#"
        #else:
        #    # Nothing to whitelist (breaks stuff, do not uncomment)
        #    if (debug >= 2): log_info('Removed whitelist-entry \"' + domain + '\", no blacklist hit')
        #    del whitelist[domain]

    # Remove blacklisted entries when matched against whitelist regex
    newlistb = unreg_lists(dict.fromkeys(listb, 'Uncomplicate'), rwhitelist, safelist, 'UncompBlackDoms')
    listb = newlistb.keys()

    # New/Work dictionary
    new = dict()

    # Build new dictionary preserving id/category
    for domain in listb:
        if domain in blacklist:
            new[domain] = blacklist[domain]
        else:
            new[domain] = 'SafeList'

    before = len(blacklist)
    after = len(new)
    count = after - before

    if (debug >= 2): log_info('Number of black-listed domains went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return new


# Remove excluded entries from domain-lists
def exclude_domlist(domlist, exlist, bw):
    if not exlist:
        return domlist, dict()

    log_info('\nExcluding \"' + bw + '\"')

    newlist = dict()
    sdomlist = dict()
    for domain in domlist.keys():
        found = dom_find(domain, exlist, 'exclude')
        if found:
            #ebw = exlist.get(found, 'exclude')
            #if ebw == 'exclude' or ebw != bw:
            #    if (debug >= 2): log_info(bw + 'list: Excluded \"' + domain + '\" - Matched against ' + ebw + 'listed \"' + found + '\"')
            #else:
            #    newlist[domain] = domlist[domain]
            if (debug >= 2): log_info(bw + 'list: Excluded \"' + domain + '\" - Matched against \"' + found + '\"')
            sdomlist[domain] = domlist[domain]
        else:
            newlist[domain] = domlist[domain]

    before = len(domlist)
    after = len(newlist)
    deleted = before - after

    log_info(bw + 'list went from ' + str(before) + ' to ' + str(after) + ', after removing ' + str(deleted) + ' excluded entries\n')

    return newlist, sdomlist


# Uncomplicate IP lists, remove whitelisted IP's from blacklist
def uncomplicate_ip_lists(cwhitelist, cblacklist, listname, size):
    log_info('\nUncomplicating ' + listname + ' black/whitelists')

    listw = list(cwhitelist)
    listb = list(cblacklist)

    # Remove all 1-to-1/same whitelisted entries from blacklist
    # !!! We need logging on this !!!
    listb = dom_sort(list(set(listb).difference(listw)))

    # loop through blacklist entries and find whitelisted entries to remove
    for ip in listb:
        if ip in listw:
            if (debug >= 3): log_info('Removed blacklist-entry \"' + ip + '\" due to white-listed \"' + cwhitelist[ip] + '\"')
            listb.remove(ip)

    new = pytricia.PyTricia(size)

    # Build new dictionary preserving id/category
    for ip in listb:
        new[ip] = cblacklist[ip]

    before = len(cblacklist)
    after = len(new)
    count = after - before

    if (debug >= 2): log_info('Number of black-listed ' + listname + ' went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return new


# Remove entries from domains already matching by a regex
def unreg_lists(dlist, rlist, safelist, listname):
    if not rlist:
        return dlist

    log_info('\nUnregging \"' + listname + '\"')

    before = len(dlist)

    for i in range(0, len(rlist)/3):
        checkregex = rlist[i ,1]
        #if rlist[i,2].find('(?!') == -1:
        if (debug >= 3): log_info('Checking against \"' + rlist[i, 2] + '\"')
        for found in filter(checkregex.search, dlist):
            name = dlist[found]
            if dom_find(name, safelist, listname) is False:
                del dlist[found]
                if (debug >= 3): log_info('Removed \"' + found + '\" from \"' + name + '\" matched by regex \"' + rlist[i, 2] + '\"')
            else:
                if (debug >= 3): log_info('Preserved safelisted \"' + found + '\" from \"' + name + '\" matched by regex \"' + rlist[i, 2] + '\"')
        #else:
        #    if (debug >= 2): log_info('Skipped negative-lookahead regex \"' + rlist[i,2] + '\"')

    after = len(dlist)
    count = after - before

    if (debug >= 2): log_info('Number of \"' + listname + '\" entries went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return dlist


def is_active(domlist, listname):
    newdomlist = dict()
    total = len(domlist)
    if total > 0:
        count = 0
        for dom in dom_sort(domlist.keys()):
            count += 1
            #result = socket.getaddrinfo('{0}.'.format(dom.rstrip('.')), 53, type=socket.SOCK_STREAM)
            result = socket.getaddrinfo('{0}.'.format(dom.rstrip('.')), 53, type=socket.SOCK_STREAM) #or socket.getaddrinfo('{0}.'.format(dom.rstrip('.')), 53, type=socket.IPPROTO_TCP)
            if result:
                #ips = list((map(lambda x: x[4][0] + '@' + str(x[4][1]), result)))
                ips = list((map(lambda x: x[4][0], result)))
                if ips:
                    log_info('ACTIVE [' + listname + ' ' + str(count) + '/' + str(total) + ']: ' + dom + ' (' + ', '.join(ips) + ')')
                    newdomlist[dom] = domlist[dom]
                else:
                    log_info('INACTIVE [' + listname + ' ' + str(count) + '/' + str(total) + ']: ' + dom)

    else:
        return domlist

    return newdomlist


def asnnum(asnstr):
    return int(regex.sub('^AS', '', asnstr))


# Save out generic/plain files
# !!! TEST - Needs try/except added
# !!! Maybe use dict and simplyfy in a loop for different lists
def plain_save(bw, optimized):
    if optimized is True:
        log_info('\nCreating optimized ' + bw + '-lists in ' + outputdir)
    else:
        log_info('\nCreating plain ' + bw + '-lists in ' + outputdir)

    if bw == 'white':
        if not whitelist:
            log_info('\nREVERTING TO SAFEWHITELIST!')
            domlist = safewhitelist
        else:
            domlist = whitelist
        asnlist = asnwhitelist
        iplist4 = cwhitelist4
        iplist6 = cwhitelist6
        rxlist = rwhitelist
        exlist = optimize_domlists(excludelist, 'ExcludeDoms')
    else:
        if not blacklist:
            log_info('\nREVERTING TO SAFEBLACKLIST!')
            domlist = safeblacklist
        else:
            domlist = blacklist

        domlist = blacklist
        asnlist = asnblacklist
        iplist4 = cblacklist4
        iplist6 = cblacklist6
        rxlist = rblacklist
        exlist = dict()

    fprefix = "/plain."
    if optimized is True:
        fprefix = "/optimized."

    fprefix = fprefix + bw
    log_info('-- ' + fprefix + '.*.list')

    if len(domlist) > 0:
        punylist=set()
        with open(outputdir + fprefix + '.domain.list', 'w') as f:
            for domain in dom_sort(domlist.keys()):
                if ispuny.match(domain):
                    punylist.add(domain)

                f.write(domain)
                f.write('\n')

        if punylist:
            with codecs.open(outputdir + fprefix + '.idn.domain.list', 'w', encoding="utf-8") as f:
                for domain in dom_sort(punylist):
                    try:
                        idn=idna.decode(domain)

                    except:
                        log_err('PUNY-ERROR: \"' + domain + '\"')

                    else:
                        log_info('PUNY: \"' + domain + '\" -> \"' + idn + '\"')
                        f.write(idn)
                        f.write('\n')

        if bw == 'black' and topdoms:
            with open(outputdir + fprefix + '.top-n.domain.list', 'w') as f:
                #for domain in dom_sort(domlist.keys()):
                #    if dom_find(domain, top1mlist, 'top1mlist'):
                for domain in dom_sort(topdoms.keys()):
                    f.write('{0}'.format(domain.strip('.')))
                    f.write('\n')

    if len(exlist) > 0 and optimized is False:
        with open(outputdir + '/plain.exclude.domain.list', 'w') as f:
            for domain in dom_sort(exlist.keys()):
                f.write(domain)
                f.write('\n')
        
    if len(asnlist) > 0 and optimized is False:
        with open(outputdir + fprefix + '.asn.list', 'w') as f:
            for asn in asnlist.keys():
                f.write(asn)
                f.write('\n')


    if (len(iplist4) > 0 or len(iplist6) > 0) and optimized is False:
        with open(outputdir + fprefix + '.ipcidr.list', 'w') as f:
            for ip in iplist4.keys():
                f.write(ip)
                f.write('\n')
            for ip in iplist6.keys():
                f.write(ip)
                f.write('\n')

    if len(iplist4) > 0 and optimized is False:
        with open(outputdir + fprefix + '.ip4cidr.list', 'w') as f:
            for ip in iplist4.keys():
                f.write(ip)
                f.write('\n')

        with open(outputdir + fprefix + '.ip4range.list', 'w') as f:
            for ip in iplist4.keys():
                f.write(IP(ip).strNormal(3))
                f.write('\n')

    if len(iplist6) > 0 and optimized is False:
        with open(outputdir + fprefix + '.ip6cidr.list', 'w') as f:
            for ip in iplist6.keys():
                f.write(ip)
                f.write('\n')

        with open(outputdir + fprefix + '.ip6range.list', 'w') as f:
            for ip in iplist6.keys():
                f.write(IP(ip).strNormal(3))
                f.write('\n')

    if len(rxlist) > 0 and optimized is False:
        with open(outputdir + fprefix + '.regex.list', 'w') as f:
            for rx in range(0, len(rxlist)/3):
                f.write(rxlist[rx, 2])
                f.write('\n')

    if bw == "black" and optimized is False:
        with open(outputdir + '/plain.skipped.invalid.domain.list', 'w') as f:
            f.write("# ONLY USE FOR REFERENCE!")
            f.write('\n')
            for domain in dom_sort(invalidskipped.keys()):
                f.write(domain + "\t# " + invalidskipped[domain])
                f.write('\n')




    return True


def routedns_save(optimized):
    pref = ''
    if optimized:
        pref = '.optimized'
        log_info('\nCreating Optimized RouteDNS lists in ' + outputdir)
    else:
        log_info('\nCreating RouteDNS lists in ' + outputdir)

    if optimized and len(rwhitelist) > 0:
        with open(outputdir + '/routedns.allowlist.regexp.list', 'w') as f:
            for rx in range(0, len(rwhitelist)/3):
                f.write(rwhitelist[rx, 2])
                f.write('\n')

    if optimized and len(rblacklist) > 0:
        with open(outputdir + '/routedns.blocklist.regexp.list', 'w') as f:
            for rx in range(0, len(rblacklist)/3):
                f.write(rblacklist[rx, 2])
                f.write('\n')

    justdoms = set()
    if len(whitelist) > 0:
        with open(outputdir + '/routedns.allowlist' + pref + '.domain.list', 'w') as f:
            for domain in dom_sort(whitelist.keys()):
                f.write('.{0}'.format(domain.strip('.')))
                f.write('\n')
                bdom = dom_find(domain, blacklist, 'BLACKLIST')
                if bdom and bdom != domain:
                    if (debug >= 2): log_info('AllowList-JustDomain: \"{0}\" (Blacklisted: {1})'.format(domain, bdom))
                    justdoms.add(domain)

            if optimized:
                with open(outputdir + '/routedns.blocklist' + pref + '.tld.domain.list', 'w') as f:
                    for domain in dom_sort(whitelist.keys()):
                        if '.' not in domain:
                            f.write('.{0}'.format(domain.strip('.')))
                            f.write('\n')

    if len(justdoms) > 0:
        with open(outputdir + '/routedns.allowlist' + pref + '.justdomain.list', 'w') as f:
            for domain in dom_sort(justdoms):
                f.write('{0}'.format(domain.strip('.')))
                f.write('\n')

    justdoms = set()
    if len(blacklist) > 0:
        with open(outputdir + '/routedns.blocklist' + pref + '.domain.list', 'w') as f:
            for domain in dom_sort(blacklist.keys()):
                f.write('.{0}'.format(domain.strip('.')))
                f.write('\n')
                wdom = dom_find(domain, whitelist, 'WHITELIST')
                if wdom and wdom != domain:
                    if (debug >= 2): log_info('BlockList-JustDomain: \"{0}\" (Whitelisted: {1})'.format(domain, wdom))
                    justdoms.add(domain)

        if topdoms:
            with open(outputdir + '/routedns.blocklist' + pref + '.top-n.domain.list', 'w') as f:
                #for domain in dom_sort(blacklist.keys()):
                #    if dom_find(domain, top1mlist, 'top1mlist'):
                for domain in dom_sort(topdoms.keys()):
                        f.write('.{0}'.format(domain.strip('.')))
                        f.write('\n')

            if optimized:
                with open(outputdir + '/routedns.blocklist' + pref + '.tld.domain.list', 'w') as f:
                    for domain in dom_sort(blacklist.keys()):
                        if '.' not in domain:
                            f.write('.{0}'.format(domain.strip('.')))
                            f.write('\n')

    if len(justdoms) > 0:
        with open(outputdir + '/routedns.blocklist' + pref + '.justdomain.list', 'w') as f:
            for domain in dom_sort(justdoms):
                f.write('{0}'.format(domain.strip('.')))
                f.write('\n')


    return True


# Little Snitch
def ls_save(listname, bw, topn):
    log_info('\nCreating Little-Snitch ' + bw + '-config in ' + outputdir)

    suffixname = ''
    if bw == 'white':
        action = "allow"
        domlist = whitelist
        iplist4 = cwhitelist4
        iplist6 = cwhitelist6
    else:
        action = "deny"
        if topn:
            suffixname = '-top-n'
            domlist = topdoms
            iplist4 = dict()
            iplist6 = dict()
        else:
            domlist = blacklist
            iplist4 = cblacklist4
            iplist6 = cblacklist6

    with open(outputdir + '/litte-snitch.' + bw + suffixname + '.domains.lsrules', 'w') as f:
        f.write('{\n')
        f.write('\t\"name\" : \"Accomplist ' + listname +' ' + bw + suffixname + '-list\",\n')
        f.write('\t\"description\" : \"Accomplist *' + listname + suffixname + '* ' + bw + 'list (' + str(int(time.time())) + '). See: https://github.com/cbuijs/accomplist\",\n')

        if len(domlist) > 0 and len(domlist) < 200000:
            f.write('\t\"denied-remote-domains\" : [')
            for domain in domlist.keys():
                f.write('\"' + domain + '\", ')

            f.write('\"dummy\"]\n')

        f.write('}\n')

    if topn is False and (len(iplist4) + len(iplist6) < 200000):
        with open(outputdir + '/litte-snitch.' + bw + suffixname + '.ipcidr.lsrules', 'w') as f:
            f.write('{\n')
            f.write('\t\"name\" : \"Accomplist ' + bw + suffixname + '-list\",\n')
            f.write('\t\"description\" : \"Accomplist *' + listname + suffixname + '* ' + bw + 'list (' + str(int(time.time())) + '). See: https://github.com/cbuijs/accomplist\",\n')

            if len(iplist4) > 0 or len(iplist6) > 0:
                f.write('\t\"denied-remote-addresses\" : [')

            if len(iplist4) > 0:
                for ip in iplist4.keys():
                    f.write('\"' + ip + '\", ')

            if len(iplist6) > 0:
                for ip in iplist6.keys():
                    f.write('\"' + ip + '\", ')

            if len(iplist4) > 0 or len(iplist6) > 0:
                f.write('\"0.0.0.0\"]\n')

            f.write('}\n')

    return True


# Save HostsFile
def hosts_save():
    log_info('\nCreating plain.hosts and plain.hostdomains in ' + outputdir)
    if blacklist:
        tdoms = make_top(blacklist, 'Hosts BlackList')

        with open(outputdir + '/plain.black.hosts.list', 'w') as f:
            for domain in dom_sort(blacklist.keys()):
                f.write('0.0.0.0\t' + domain + '\n')
                #f.write('::\t' + domain + '\n')

        with open(outputdir + '/plain.black.top-n.hosts.list', 'w') as f:
            for domain in dom_sort(tdoms.keys()):
                f.write('0.0.0.0\t' + domain + '\n')
                #f.write('::\t' + domain + '\n')

        with open(outputdir + '/plain.black.hostdomains.list', 'w') as f:
            for domain in dom_sort(blacklist.keys()):
                f.write(domain + '\n')

        with open(outputdir + '/plain.black.top-n.hostdomains.list', 'w') as f:
            for domain in dom_sort(tdoms.keys()):
                f.write(domain + '\n')

    if whitelist:
        tdoms = make_top(whitelist, 'Hosts WhiteList')

        with open(outputdir + '/plain.white.hosts.list', 'w') as f:
            for domain in dom_sort(whitelist.keys()):
                f.write('0.0.0.0\t' + domain + '\n')
                #f.write('::\t' + domain + '\n')

        with open(outputdir + '/plain.white.top-n.hosts.list', 'w') as f:
            for domain in dom_sort(tdoms.keys()):
                f.write('0.0.0.0\t' + domain + '\n')
                #f.write('::\t' + domain + '\n')

        with open(outputdir + '/plain.white.hostdomains.list', 'w') as f:
            for domain in dom_sort(whitelist.keys()):
                f.write(domain + '\n')

        with open(outputdir + '/plain.white.top-n.hostdomains.list', 'w') as f:
            for domain in dom_sort(tdoms.keys()):
                f.write(domain + '\n')

    return True


# Save adblock
def adblock_save():
    log_info('\nCreating adblock.txt in ' + outputdir)
    with open(outputdir + '/adblock.txt', 'w') as f:
        f.write('[Adblock Plus 1.1]\n')
        f.write('! Title: Accomplist \"' + sourcename.title() + '\" AdBlock List (Top-N Version)\n')
        f.write('! Version: ' + str(int(time.time())) + '\n')
        f.write('! Homepage: https://github.com/cbuijs/accomplist/tree/master/' + sourcename.lower() + '\n')

        if rwhitelist:
            f.write('!\n! Whitelist Regexes:\n')
            for line in range(0, len(rwhitelist)/3):
                f.write('@@/' + regex.sub('\$$', '\/', rwhitelist[line,2]) + '/$important\n')

        denyallow = dict()
        if blacklist and whitelist:
            for domain in blacklist.keys():
                whitelisted = dom_find(domain, whitelist, 'whitelist')
                if whitelisted and domain != whitelisted:
                    if whitelisted in denyallow:
                        denyallow[whitelisted] = denyallow[whitelisted] + '|' + domain
                    else:
                        denyallow[whitelisted] = domain


        if whitelist:
            f.write('!\n! WhiteList Domains:\n')
            for domain in dom_sort(whitelist.keys()):
                if domain.count('.') < 1:
                     domain = '*.' + domain

                if domain in denyallow:
                    f.write('@@||' + domain + '^$denyallow=' + denyallow[domain] + '^\n')
                else:
                    f.write('@@||' + domain + '^\n')

        #if cwhitelist4:
        #    f.write('!\n! WhiteList IPv4 Addresses:\n')
        #    for cidr in cwhitelist4.keys():
        #        if cidr.endswith('/32'):
        #            ip = regex.split('/', cidr)[0]
        #            f.write('@@' + ip + '^$network,important\n')

        #if cwhitelist6:
        #    f.write('!\n! WhiteList IPv6 Addresses:\n')
        #    for cidr in cwhitelist6.keys():
        #        if cidr.endswith('/128'):
        #            ip = regex.split('/', cidr)[0]
        #            f.write('@@[' + ip + ']^$network,important\n')

        if rblacklist:
            f.write('!\n! BlackList Regexes:\n')
            for line in range(0, len(rblacklist)/3):
                f.write('/' + regex.sub('\$$', '\/', rblacklist[line,2]) + '/\n')

        #if blacklist:
        #    f.write('!\n! BlackList Domains:\n')
        #    for domain in blacklist.keys():
        #        f.write('||' + domain + '^\n')

        if blacklist and topdoms:
            f.write('!\n! BlackList TLDs:\n')
            for domain in dom_sort(blacklist.keys()):
                if domain.count('.') < 1:
                    f.write('||*.' + domain + '^\n')

            if len(blacklist) > 100000:
                f.write('!\n! BlackList Top-N Domains (Reduced, original is more then 100K rules):\n')
                for domain in dom_sort(topdoms.keys()):
                    if domain.count('.') > 0:
                        f.write('||' + domain + '^\n')
            else:
                f.write('!\n! BlackList Domains:\n')
                for domain in dom_sort(blacklist.keys()):
                    if domain.count('.') > 0:
                        f.write('||' + domain + '^\n')

        #if cblacklist4:
        #    f.write('!\n! BlackList IPv4 Addresses:\n')
        #    for cidr in cblacklist4.keys():
        #        if cidr.endswith('/32'):
        #            ip = regex.split('/', cidr)[0]
        #            f.write(ip + '$network\n')

        #if cblacklist6:
        #    f.write('!\n! BlackList IPv6 Addresses:\n')
        #    for cidr in cblacklist6.keys():
        #        if cidr.endswith('/128'):
        #            ip = regex.split('/', cidr)[0]
        #            f.write('[' + ip + ']$network\n')

        f.write('!\n! EOF\n')

    return True


# Save knot-resolver DAF rules
def knot_save():
    log_info('\nCreating knot-daf.conf in ' + outputdir)
    with open(outputdir + '/knot-daf.conf', 'w') as f:
        f.write('-- Whitelisted Domains\n')
        for domain in dom_sort(whitelist.keys()):
            f.write('daf.add \'qname = ' + domain + ' pass\'\t -- ' + whitelist[domain] + '\n')

        f.write('-- BlackListed Domains\n')
        for domain in dom_sort(blacklist.keys()):
            f.write('daf.add \'qname = ' + domain + ' deny\'\t -- ' + blacklist[domain] + '\n')

        f.write('-- EOF')

    return True


# Save DeugNietS
def deugniets_save(bw, domlist, ip4list, ip6list, rxlist):
    filename = 'deugniets.' + bw + '.list'
    log_info('\nCreating ' + filename + ' in ' + outputdir)

    with open(outputdir + '/' + filename, 'w') as f:
        f.write('# DEUGNIETS ' + bw.upper() + 'LIST\n')
        if rxlist:
            f.write('\n# REGEXES\n')
            for line in range(0, len(rxlist)/3):
                f.write('/' + rxlist[line,2] + '/\n')

        if domlist:
            f.write('\n# DOMAINS\n')
            #for line in dom_sort(domlist.keys()):
            for line in dom_sort(domlist.keys()):
                f.write(line + '\n')

        if ip4list:
            f.write('\n# IPV4 ADDRESSES\n')
            for line in ip4list.keys():
                f.write(line + '\n')

        if ip6list:
            f.write('\n# IPV6 ADDRESSES\n')
            for line in ip6list.keys():
                f.write(line + '\n')

    return True


# Save coredns
def coredns_save(dorx):
    if dorx:
        filename = 'coredns-template-filter.conf'
    else:
        filename = 'coredns-safe-template-filter.conf'

    log_info('\nCreating ' + filename + ' in ' + outputdir)
    with open(outputdir + '/' + filename, 'w') as f:
        f.write('# COREDNS CONFIG FILE\n')
        if dorx and rblacklist:
            f.write('\n# REGEX-BLACKLIST \n')
            f.write('template IN ANY . {\n')
            for line in range(0, len(rblacklist)/3):
                f.write('\tmatch ' + regex.sub('\$$', '\\.$', rblacklist[line,2], regex.I) + '\n')

            f.write('\n\trcode NXDOMAIN\n')
            #f.write('\tauthority \"{{ .Name }} 3600 IN SOA blocked.rx.{{ .Type }}.{{ .Name }} nxdomain.{{ .Name }} (1 60 60 60 60)\"\n')
            f.write('\tauthority "{{ .Zone }} 3600 IN SOA {{ .Name }}{{ .Class }}.{{ .Type }}. blocked.nxdomain. (1 60 60 60 60)\"\n')
            f.write('\n\tfallthrough\n')
            f.write('}\n')

        if blacklist:
            f.write('\n# DOMAIN-BLACKLIST\n')
            f.write('template IN ANY ' + ' '.join(blacklist.keys()) + ' {\n')
            #f.write('template IN ANY . {\n')
            #for line in dom_sort(blacklist.keys()):
                #f.write('\tmatch ^(.*\\.)*(?P<dom>' + regex.escape(line) + '\\.)$' + '\n')
            #    f.write('template ANY ANY ' + line + ' { rcode NXDOMAIN }\n')

            f.write('\n\trcode NXDOMAIN\n')
            #f.write('\tauthority \"{{ .Name }} 3600 IN SOA blocked.dom.{{ .Type }}.{{ .Name }} nxdomain.{{ .Name }} (1 60 60 60 60)\"\n')
            f.write('\tauthority "{{ .Zone }} 3600 IN SOA {{ .Name }}{{ .Class }}.{{ .Type }}. blocked.nxdomain. (1 60 60 60 60)\"\n')
            #f.write('\n\tfallthrough\n')
            f.write('}\n')

    return True 

    if not dorx:
        log_info('\nCreating coredns-file-filter.conf in ' + outputdir)
        with open(outputdir + '/coredns-file-filter.conf', 'w') as f:
            f.write('# COREDNS CONFIG FILE\n')
            if blacklist:
                f.write('\n# DOMAIN-BLACKLIST\n')
                for line in dom_sort(blacklist.keys()):
                    f.write('file db.block ' + line + '\n')

        log_info('\nCreating coredns-acl.conf in ' + outputdir)
        with open(outputdir + '/coredns-acl.conf', 'w') as f:
            f.write('# COREDNS CONFIG FILE\n')
            if cblacklist4 or cwhitelist4 or cblacklist6 or cwhitelist6:
                f.write('\n# IP-WHITE/BLACKLIST\n')
                f.write('acl {\n')
                for cidr in cwhitelist4.keys():
                    f.write('\tallow net ' + cidr + '\n')

                for cidr in cwhitelist6.keys():
                    f.write('\tallow net ' + cidr + '\n')

                for cidr in cblacklist4.keys():
                    f.write('\tblock net ' + cidr + '\n')

                for cidr in cblacklist6.keys():
                    f.write('\tblock net ' + cidr + '\n')
                f.write('}\n')

            if whitelist:
                f.write('\n# DOMAIN-WHITELIST\n')
                for line in dom_sort(whitelist.keys()):
                    f.write('acl ' + line + ' {\n')
                    f.write('\tallow net *\n')
                    f.write('}\n')

            if blacklist:
                f.write('\n# DOMAIN-BLACKLIST\n')
                for line in dom_sort(blacklist.keys()):
                    f.write('acl ' + line + ' {\n')
                    f.write('\tblock net *\n')
                    f.write('}\n')

        return True


    log_info('\nCreating coredns-policy-filter.conf in ' + outputdir)
    with open(outputdir + '/coredns-policy-filter.conf', 'w') as f:
        f.write('# Needs "policy" plugin: https://github.com/coredns/policy\n\n')
        f.write('firewall query {\n')
        if rwhitelist:
            f.write('\n\t#REGEX-WHITELIST\n')
            for line in range(0, len(rwhitelist)/3):
                f.write('\tallow name =~ \'' + rwhitelist[line,2] + '\'\n')

        if whitelist:
            f.write('\n\t#DOMAIN-WHITELIST\n')
            for line in dom_sort(whitelist.keys()):
                f.write('\tallow name =~ \'^(.*\.)*' + line.replace('.', '\.') + '$\'\n')

        if rblacklist:
            f.write('\n\t#REGEX-BLACKLIST\n')
            for line in range(0, len(rblacklist)/3):
                f.write('\trefuse name =~ \'' + rblacklist[line,2] + '\'\n')

        if blacklist:
            f.write('\n\t#DOMAIN-BLACKLIST\n')
            for line in dom_sort(blacklist.keys()):
                f.write('\trefuse name =~ \'^(.*\.)*' + line.replace('.', '\.') + '$\'\n')

        f.write('\n\tallow true\n')
        f.write('}\n')


    log_info('\nCreating coredns-ads-filter.conf in ' + outputdir)
    with open(outputdir + '/coredns-ads-filter.conf', 'w') as f:
        f.write('# Needs "ads" plugin: https://github.com/c-mueller/ads\n\n')
        f.write('ads {\n')
        if rwhitelist:
            f.write('\n\t#CONFIG\n')
            f.write('\tlog\n')
            f.write('\tdisable-auto-update\n')
            f.write('\tlist https://0.0.0.0\n')
            f.write('\ttarget 0.0.0.0\n')
            f.write('\ttarget-ipv6 ::\n')
            f.write('\n\t#REGEX-WHITELIST\n')
            for line in range(0, len(rwhitelist)/3):
                f.write('\twhitelist-regex ' + rwhitelist[line,2] + '\n')

        if whitelist:
            f.write('\n\t#DOMAIN-WHITELIST\n')
            for line in dom_sort(whitelist.keys()):
                f.write('\twhitelist ' + line + '\n')

        if rblacklist:
            f.write('\n\t#REGEX-BLACKLIST\n')
            for line in range(0, len(rblacklist)/3):
                f.write('\tblacklist-regex ' + rblacklist[line,2] + '\n')

        if blacklist:
            f.write('\n\t#DOMAIN-BLACKLIST\n')
            for line in dom_sort(blacklist.keys()):
                f.write('\tblacklist ' + line + '\n')

        f.write('}\n')

    return True


# Save unbound
def unbound_save():
    log_info('\nCreating unbound-filter.conf in ' + outputdir)

    with open(outputdir + '/unbound-filter.conf', 'w') as f:
        f.write('server:\n')
        #if whitelist:
        #    f.write('\t### Whitelisted Domains ###\n')
        #    for domain in dom_sort(whitelist.keys()):
        #        f.write('\tlocal-zone: \"' + domain + '\" inform\t# ' + whitelist[domain] + '\n')

        if blacklist:
            f.write('\n\t### BlackListed Domains ###\n')
            for domain in dom_sort(blacklist.keys()):
                f.write('\tlocal-zone: \"' + domain + '\" always_nxdomain\t# ' + blacklist[domain] + '\n')

        if cblacklist4:
            f.write('\n\t### BlackListed IPv4 ###\n')
            for cidr in cblacklist4.keys():
                f.write('\tprivate-address: ' + cidr + '\t# ' + cblacklist4[cidr] + '\n')

        if cblacklist6:
            f.write('\n\t### BlackListed IPv6 ###\n')
            for cidr in cblacklist6.keys():
                f.write('\tprivate-address: ' + cidr + '\t# ' + cblacklist6[cidr] + '\n')

        f.write('\n### EOF ###')


# Save DNSMasq
def dnsmasq_save():
    log_info('\nCreating dnsmasq-filter.conf in ' + outputdir)

    with open(outputdir + '/dnsmasq-filter.conf', 'w') as f:
        f.write('### DNSMASQ CONFIG\n')

        if whitelist:
            f.write('### WhiteListed Domains ###\n')
            for domain in dom_sort(whitelist.keys()):
                f.write('server=/' + domain + '/#\t# ' + whitelist[domain] + '\n')

        if blacklist:
            f.write('### BlackListed Domains ###\n')
            for domain in dom_sort(blacklist.keys()):
                f.write('server=/' + domain + '/\t# ' + blacklist[domain] + '\n')

        if cblacklist4:
            f.write('### BlackListed IPs ###\n')
            for cidr in cblacklist4.keys():
                if cidr.endswith('/32'):
                    ip = regex.split('/', cidr)[0]
                    f.write('bogus-nxdomain=' + ip + '\t# ' + cblacklist4[cidr] + '\n')

        f.write('### EOF ###')

    return True


# Save DNSMasq, regex version
def dnsmasq_regex_save():
    log_info('\nCreating dnsmasq-regex-filter.conf in ' + outputdir)

    with open(outputdir + '/dnsmasq-regex-filter.conf', 'w') as f:
        f.write('### DNSMASQ-REGEX CONFIG\n')

        if rwhitelist:
            f.write('### Whitelisted Regexes ###\n')
            for line in range(0, len(rwhitelist)/3):
                f.write('server=/:' + rwhitelist[line,2] + ':/#\t# ' + rwhitelist[line,0] + '\n')

        if whitelist:
            f.write('### WhiteListed Domains ###\n')
            for domain in dom_sort(whitelist.keys()):
                f.write('server=/' + domain + '/#\t# ' + whitelist[domain] + '\n')

        if rblacklist:
            f.write('### BlackListed Regexes ###\n')
            for line in range(0, len(rblacklist)/3):
                f.write('server=/:' + rblacklist[line,2] + ':/\t# ' + rblacklist[line,0] + '\n')

        if blacklist:
            f.write('### BlackListed Domains ###\n')
            for domain in dom_sort(blacklist.keys()):
                f.write('server=/' + domain + '/\t# ' + blacklist[domain] + '\n')

        if cblacklist4:
            f.write('### BlackListed IPs ###\n')
            for cidr in cblacklist4.keys():
                ip = False
                if cidr.endswith('/32'):
                    ip = regex.split('/', cidr)[0]
                    f.write('bogus-nxdomain=' + ip + '\t# ' + cblacklist4[cidr] + '\n')

        f.write('### EOF ###')

    return True

# Squid
def squid_save():
    log_info('\nCreating squid.*.acl files in' + outputdir)

    # Whitelists
    if rwhitelist:
        with open(outputdir + '/squid.white.dstdom_regex.acl', 'w') as f:
            for line in range(0, len(rwhitelist)/3):
                f.write(rwhitelist[line,2] + '\n')

    if whitelist:
        with open(outputdir + '/squid.white.dstdomain.acl', 'w') as f:
            for line in dom_sort(whitelist.keys()):
                f.write('.' + line + '\n')

    if cwhitelist4 or cwhitelist6:
        with open(outputdir + '/squid.white.dst.acl', 'w') as f:
            for cidr in cwhitelist4.keys():
                f.write(cidr + '\n')
            for cidr in cwhitelist6.keys():
                f.write(cidr + '\n')

    # Blacklists
    if rblacklist:
        with open(outputdir + '/squid.black.dstdom_regex.acl', 'w') as f:
            for line in range(0, len(rblacklist)/3):
                f.write(rblacklist[line,2] + '\n')

    if blacklist:
        with open(outputdir + '/squid.black.dstdomain.acl', 'w') as f:
            for line in dom_sort(blacklist.keys()):
                f.write('.' + line + '\n')

    if cblacklist4 or cblacklist6:
        with open(outputdir + '/squid.black.dst.acl', 'w') as f:
            for cidr in cblacklist4.keys():
                f.write(cidr + '\n')
            for cidr in cblacklist6.keys():
                f.write(cidr + '\n')

# Save bind rpz file
def rpz_save(bw, topn, clientip):

    ci = ''
    if clientip:
        ci = 'clientip.'

    if bw == 'white':
        if topn:
            file = outputdir + '/db.' + bw + '.' + ci + 'top-n.rpz'
        else:
            file = outputdir + '/db.' + bw + '.' + ci + 'rpz'

        fulllist = whitelist
        domlist = whitelist
        iplist4 = cwhitelist4
        iplist6 = cwhitelist6
        lname = "WHITELIST"
    else:
        if topn:
            file = outputdir + '/db.' + bw + '.' + ci + 'top-n.rpz'
            domlist = topdoms
        else:
            file = outputdir + '/db.' + bw + '.' + ci + 'rpz'
            domlist = blacklist

        fulllist = blacklist
        iplist4 = cblacklist4
        iplist6 = cblacklist6
        lname = "BLACKLIST"


    log_info('\nCreating RPZ File \"' + file + '\"')

    justdoms = set()
    with open(file, 'w') as f:
        serial = int(time.time())
        dummyns = str('dummy-' + str(serial) + '-ns')

        f.write('; BIND RPZ ' + bw + 'list\n')
        f.write('$TTL 3600\n')
        f.write('@ SOA ' + dummyns + ' hostmaster ' + str(serial) + ' 12h 15m 3w 3h\n')
        f.write('@ NS ' + dummyns + '\n')
        f.write(dummyns + ' A 0.0.0.0\n')
        f.write(dummyns + ' AAAA ::\n')

        f.write(';\n; --- TLDS ---\n')
        for domain in dom_sort(fulllist.keys()):
            if '.' not in domain:
                f.write(domain + ' CNAME .\n') #\t; ' + domlist[domain] + '\n')
                f.write('*.' + domain + ' CNAME .\n') #\t; ' + domlist[domain] + '\n')


        f.write(';\n; --- DOMAINS ---\n')
        for domain in dom_sort(domlist):
            #if isdomain.match(domain) and len(domain) < 192:
            if "." in domain:
                if len(domain) < 192:
                    f.write(domain + ' CNAME .\n') #\t; ' + domlist[domain] + '\n')
                    f.write('*.' + domain + ' CNAME .\n') #\t; ' + domlist[domain] + '\n')

                    if bw == 'white':
                        bdom = dom_find(domain, blacklist, 'BLACKLIST')
                        if bdom and bdom != domain:
                            if (debug >= 2): log_info('Whitelist-JustDomain: \"{0}\" (Blacklisted: {1})'.format(domain, bdom))
                            justdoms.add(domain)

                    else:
                        bdom = dom_find(domain, whitelist, 'WHITELIST')
                        if bdom and bdom != domain:
                            if (debug >= 2): log_info('Blacklist-JustDomain: \"{0}\" (Whitelisted: {1})'.format(domain, bdom))
                            justdoms.add(domain)

                else:
                    log_info('\nINVALID DOMAIN: ' + domain + ' (' + domlist[domain] + ')')


        f.write(';\n; --- IPv4 ---\n')
        for cidr in iplist4:
            if cidr.find('/') < 0:
                cidr = cidr + '/32'

            ip = '.'.join(regex.sub('/', '.', cidr).split('.')[::-1])
            if clientip:
                f.write(ip + '.rpz-client-ip CNAME .\n') #\t; ' + cidr +'\n')
            else:
                f.write(ip + '.rpz-ip CNAME .\n') #\t; ' + cidr +'\n')

        f.write(';\n; --- IPv6 ---\n')
        for cidr in iplist6:
            if cidr.find('/') < 0:
                cidr = cidr + '/128'
            ip = regex.sub(r'\.0+([0-9a-f]+)', r'.\1', regex.sub(r'\.[0\.]+\.', '.zz.', '.'.join(regex.sub('[:/]', '.', expand_ip(cidr)).split('.')[::-1]) + '.', count=1)).strip('.')
            if clientip:
                f.write(ip + '.rpz-client-ip CNAME .\n') #\t; ' + cidr +'\n')
            else:
                f.write(ip + '.rpz-ip CNAME .\n') #\t; ' + cidr +'\n')

        f.write(';\n; --- EOF ---\n')

    if len(justdoms) > 0:
        file = outputdir + '/db.' + bw + '.justdomain.rpz'
        with open(file, 'w') as f:
            serial = int(time.time())
            dummyns = str('dummy-' + str(serial) + '-ns')

            f.write('; BIND RPZ ' + bw + 'list\n')
            f.write('$TTL 3600\n')
            f.write('@ SOA ' + dummyns + ' hostmaster ' + str(serial) + ' 12h 15m 3w 3h\n')
            f.write('@ NS ' + dummyns + '\n')
            f.write(dummyns + ' A 0.0.0.0\n')
            f.write(dummyns + ' AAAA ::\n')

            for domain in dom_sort(justdoms):
                f.write(domain + ' CNAME .\n') #\t; ' + domlist[domain] + '\n')

    return True


# Save lists to files
def write_out(whitefile, blackfile, generic):
    if whitefile:
        log_info('Saving processed whitelists to \"' + whitefile + '\"')
        try:
            with open(whitefile, 'w') as f:
                f.write('############################################\n')
                f.write('### ACCOMPLIST GENERATED WHITELIST       ###\n')
                f.write('### Version: ' + str(int(time.time())) + '                  ###\n')
                f.write('### Chris Buijs                          ###\n')
                f.write('### https://github.com/cbuijs/accomplist ###\n')
                f.write('############################################\n\n')
                if not generic:
                    f.write('### SAFELIST DOMAINS ###\n')
                    for line in dom_sort(safewhitelist.keys()):
                        f.write(line + '!\t' + safewhitelist[line])
                        f.write('\n')

                    f.write('### SAFEUNWHITELIST DOMAINS ###\n')
                    for line in dom_sort(safeunwhitelist.keys()):
                        f.write(line + '&\t' + safeunwhitelist[line])
                        f.write('\n')

                    f.write('### WHITELIST REGEXES ###\n')
                    for line in range(0, len(rwhitelist)/3):
                        f.write('/' + rwhitelist[line, 2] + '/\t' + rwhitelist[line, 0])
                        f.write('\n')

                f.write('### WHITELIST DOMAINS ###\n')
                for line in dom_sort(whitelist.keys()):
                    doit = False
                    if not generic:
                        if (line not in safewhitelist) and (line not in safeunwhitelist):
                            doit = True
                    else:
                        doit = True

                    if doit:
                        f.write(line + '\t' + whitelist[line])
                        f.write('\n')

                if not generic:
                    f.write('### WHITELIST ASN ###\n')
                    for a in sorted(asnwhitelist.keys()):
                        f.write(a + '\t' + asnwhitelist[a])
                        f.write('\n')

                f.write('### WHITELIST IPv4 ###\n')
                for a in cwhitelist4.keys():
                    f.write(a + '\t' + cwhitelist4[a].split('(')[1].split(')')[0].strip())
                    f.write('\n')
                    #f.write(IP(a).strNormal(3)) # Write out in range format x.x.x.x-y.y.y.y
                    #f.write('\n')

                f.write('### WHITELIST IPv6 ###\n')
                for a in cwhitelist6.keys():
                    f.write(a + '\t' + cwhitelist6[a].split('(')[1].split(')')[0].strip())
                    f.write('\n')

                f.write('### WHITELIST EOF ###\n')

        except BaseException as err:
            log_err('Unable to write to file \"' + whitefile + '\" - ' + str(err))

    if blackfile:
        log_info('Saving processed blacklists to \"' + blackfile + '\"')
        try:
            with open(blackfile, 'w') as f:
                f.write('############################################\n')
                f.write('### ACCOMPLIST GENERATED BLACKLIST       ###\n')
                f.write('### Version: ' + str(int(time.time())) + '                  ###\n')
                f.write('### Chris Buijs                          ###\n')
                f.write('### https://github.com/cbuijs/accomplist ###\n')
                f.write('############################################\n\n')
                if not generic:
                    f.write('### SAFELIST DOMAINS ###\n')
                    for line in dom_sort(safeblacklist.keys()):
                        f.write(line + '!\t' + safeblacklist[line])
                        f.write('\n')

                    f.write('### BLACKLIST REGEXES ###\n')
                    for line in range(0, len(rblacklist)/3):
                        f.write('/' + rblacklist[line,2] + '/\t' + rblacklist[line, 0])
                        f.write('\n')

                f.write('### BLACKLIST DOMAINS ###\n')
                for line in dom_sort(blacklist.keys()):
                    doit = False
                    if not generic:
                        if line not in safeblacklist:
                            doit = True
                    else:
                        doit = True

                    if doit:
                        f.write(line + '\t' + blacklist[line])
                        f.write('\n')

                if not generic:
                    f.write('### BLACKLIST ASN ###\n')
                    for a in sorted(asnblacklist.keys()):
                        f.write(a + '\t' + asnblacklist[a])
                        f.write('\n')

                f.write('### BLACKLIST IPv4 ###\n')
                for a in cblacklist4.keys():
                    f.write(a + '\t' + cblacklist4[a].split('(')[1].split(')')[0].strip())
                    f.write('\n')

                f.write('### BLACKLIST IPv6 ###\n')
                for a in cblacklist6.keys():
                    f.write(a + '\t' + cblacklist6[a].split('(')[1].split(')')[0].strip())
                    f.write('\n')

                f.write('### BLACKLIST EOF ###\n')

        except BaseException as err:
            log_err('Unable to write to file \"' + blackfile + '\" - ' + str(err))


    return True


# Domain sort and uniq
#def dom_sort(domlist):
#    newdomlist = list()
#    for y in sorted([x.split('.')[::-1] for x in list(dict.fromkeys(domlist, True))]):
#        newdomlist.append('.'.join(y[::-1]))
#
#    return newdomlist

def dom_sort(domlist):
    # Use a set to remove duplicates efficiently
    unique_domains = set(domlist)
    
    # Sort domains based on reversed components for sorting by TLD first
    sorted_domains = sorted(unique_domains, key=lambda domain: domain.split('.')[::-1])
    
    return sorted_domains



# Fast summarisation (list)
def ip_agg(lst):
    return list(map(str, netaddr.cidr_merge(lst)))


# Aggregate IP list (pytricia)
def aggregate_ip(iplist, listname, size):
    log_info('\nAggregating \"' + listname + '\"')

    before = len(iplist)
    new = pytricia.PyTricia(size)
    
    for ip in ip_agg(list(iplist)):
        if ip in iplist:
            new[ip] = iplist[ip]
        else:
            iplist[ip] = '(New summarized network)'
            kids = ', '.join(iplist.children(ip))
            if (debug >= 3): log_info('\"' + listname + '\": New summarized network ' + str(ip) + ' (Summarized: ' + kids + ')')

            sources = ''
            for kid in iplist.children(ip):
                sources = sources + ', ' + iplist[kid].split('(')[1].split(')')[0].strip()

            sourcenames = regex.sub(' +', ' ', ', '.join(list(set(sources.split(',')))).strip(' ,'))

            new[ip] = '(' + sourcenames + ' Summarized: ' + kids + ')'

    after = len(new)
    count = after - before

    if (debug >= 2): log_info('\"' + listname + '\": Number of IP-Entries went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return new


# convert to in-addr/ip6 
def rev_ip(ip):
    revip = list()
    eip = expand_ip(ip)
    prefix = False

    if '/' in eip:
        eip, prefix = regex.split('/', eip)[0:2]
    else:
        if ipregex4.search(eip):
            prefix = '32'
        elif ipregex6.search(eip):
            prefix = '128'

    if prefix:
        prefix = int(prefix)
        if ipregex4.search(eip):
            if prefix in (8, 16, 24, 32):
                revip.append('.'.join(eip.split('.')[0:prefix / 8][::-1]) + '.in-addr.arpa')
            else:
                p = ((prefix + 8) / 8) * 8
                if (debug > 2): log_info('REV-IP4-SPLIT: ' + eip + '/' + str(prefix) + ' --SPLIT--> /' + str(p))
                if p > 7:
                    for subnet in list(netaddr.IPNetwork(eip + '/' + str(prefix)).subnet(p)):
                        subnetip, subnetprefix = regex.split('/', str(subnet))[0:2]
                        revip.append('.'.join(str(subnetip).split('.')[0:p / 8][::-1]) + '.in-addr.arpa')


        elif ipregex6.search(eip):
            if prefix in (4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128):
                revip.append('.'.join(filter(None, regex.split('(.)', regex.sub(':', '', eip))))[0:(prefix / 4) * 2][::-1].strip('.') + '.ip6.arpa')
            else:
                p = ((prefix + 4) / 4) * 4
                if (debug > 2): log_info('REV-IP6-SPLIT: ' + eip + '/' + str(prefix) + ' --SPLIT--> /' + str(p))
                if p > 3:
                    for subnet in list(netaddr.IPNetwork(eip + '/' + str(prefix)).subnet(p)):
                        subnetip, subnetprefix = regex.split('/', expand_ip(str(subnet)))[0:2]
                        revip.append('.'.join(filter(None, regex.split('(.)', regex.sub(':', '', str(subnetip)))))[0:(p / 4) * 2][::-1].strip('.') + '.ip6.arpa')

    return revip


# Expand IPv6 address
def expand_ip(ip):
    if not ':' in ip:
        if len(ip.split('.')) != 4:
            new_ip = '0.0.0.0/32'
            log_err('IP-ERROR: ' + str(ip) + ' - ' + str(new_ip))
            return new_ip
        
        if '/' in ip:
            return ip
        else:
            return ip + '/32'

    new_ip = ip
    if new_ip.startswith(':'):
        new_ip = '0' + new_ip

    prefix = '128'
    if '/' in new_ip:
        new_ip, prefix = new_ip.split('/')[0:2]
        if new_ip.endswith(':'):
            new_ip = new_ip + '0'

    if '::' in new_ip:
        padding = 9 - new_ip.count(':')
        new_ip = new_ip.replace(('::'), ':' * padding)

    parts = new_ip.split(':')
    if len(parts) != 8:
        new_ip = '0000:0000:0000:0000:0000:0000:0000:0000/128'
        log_err('IP-ERROR: ' + str(ip) + ' - ' + str(new_ip))
        return new_ip

    for part in range(8):
        parts[part] = str(parts[part]).zfill(4)

    new_ip = ':'.join(parts) + '/' + prefix

    if (debug >= 3): log_info('IPV6-EXPANDER: {0} -> {1}'.format(ip, new_ip))

    return new_ip


# Check if file exists and return age (in seconds) if so
def file_exist(fil):
    '''Check if file exists and return age (in seconds) if so'''
    if fil:
        try:
            if os.path.isfile(fil):
                fstat = os.stat(fil)
                fsize = fstat.st_size
                if fsize > 0: # File-size must be greater then zero
                    mtime = int(fstat.st_mtime)
                    currenttime = int(time.time())
                    age = int(currenttime - mtime)
                    return age

        except BaseException as err:
            log_err('FILE-EXIST-ERROR: {0}'.format(err))
            return False

    return False


# Make directory-structures
def make_dirs(subdir):
    try:
        os.makedirs(subdir)
    except:
        return False

    return True


def to_dict(iplist):
    newdict = dict()
    for i in iplist.keys():
        newdict[i] = iplist[i]
    return newdict


def from_dict(fromlist, tolist):
    for i in fromlist.keys():
        tolist[i] = fromlist[i]
    return tolist

## Main
if __name__ == "__main__":
    log_info('\n----- ACCOMPLIST STARTED -----\n')
 
    # Header/User-Agent to use when downloading lists, some sites block non-browser downloads
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'}

    # Make sure dirs exists
    make_dirs(outputdir)
    make_dirs(workdir)

    log_info('DEBUG: ' + str(debug))
    log_info('SOURCES: ' + sources)
    log_info('OUTPUT DIR: ' + outputdir)
    log_info('WORK DIR: ' + workdir)
    log_info('SOURCENAME: ' + sourcename.title())


    # Load IPASN
    if ipasnfile:
        age = file_exist(ipasnfilecache)
        if file_exist(ipasnoutfile) and age and age < maxlistage:
            log_info('Reading ASNs from cache \"' + ipasnfilecache + '\"')
            try:
                s = shelve.open(ipasnfilecache, flag='r', protocol=2)
                asnip = s['asnip']
                ipasn4 = pytricia.PyTricia(32)
                from_dict(s['ipasn4'], ipasn4)
                ipasn6 = pytricia.PyTricia(128)
                from_dict(s['ipasn6'], ipasn6)
                s.close()

            except BaseException as err:
                log_err('ERROR: Unable to open/read file \"' + ipasnfile + '\" - ' + str(err))

        else:
            log_info('Reading IPASN file from \"' + ipasnfile + '\"')
            try:
                with open(ipasnfile, 'r') as f:
                    for line in f:
                        entry = line.strip()
                        if not (entry.startswith("#")) and not (len(entry) == 0):
                            try:
                                ip, asn = regex.split('\s+', entry)[0:2]

                                if ipregex.match(ip):
                                    lst = list()
                                    if asn in asnip:
                                        lst = asnip[asn]

                                    lst.append(ip)
                                    asnip[asn] = lst
                                else:
                                    log_err('Invalid IP ' + ip + ' - ' + entry)

                            except BaseException as err:
                                log_err('Invalid line in \"' + ipasnfile + '\": ' + entry + ' - ' + str(err))

            except BaseException as err:
                log_err('Unable to read from file \"' + ipasnfile + '\" - ' + str(err))
                ipasnfile = False

            # Sort/Aggregate
            log_info('Sorting/Aggregating ' + str(len(asnip)) + ' IPASNs')
            before = 0
            after = 0
            for asn in asnip.keys():
                lst = asnip[asn]
                before = before + len(lst)
                asnip[asn] = ip_agg(lst)
                after = after + len(asnip[asn])

            log_info('Sorted/Aggregated IPASNs from ' + str(before) + ' to ' + str(after) + ' CIDR entries')

            if ipasnoutfile:
                log_info('Writing aggregated ASN entries to \"' + ipasnoutfile + '\"')
                try:
                    with open(ipasnoutfile, 'w') as f:
                        for asn in sorted(asnip.keys(), key=int):
                            for ip in asnip[asn]:
                                f.write(ip + '\t' + asn + '\n')

                except BaseException as err:
                    log_err('Cannot open/write to \"' + ipasnoutfile + '\" - ' + str(err))

            # Create IPASN
            for asn in sorted(asnip.keys(), key=int):
                for ip in asnip[asn]:
                    bits = False
                    if ip.find('/') > 0:
                        bits = int(ip.split('/')[1])

                    if ip.find(':') == -1:
                        ipasn4[ip] = asn
                        if bits and bits < ipasnlargest4:
                            ipasnlargest4 = bits
                    else:
                        ipasn6[ip] = asn
                        if bits and bits < ipasnlargest6:
                            ipasnlargest6 = bits

            log_info('Largest IPv4 network: /' + str(ipasnlargest4))
            log_info('Largest IPv6 network: /' + str(ipasnlargest6))

            if ipasnfilecache:
                log_info('Shelving ASN entries to \"' + ipasnfilecache + '\"')
                try:
                    s = shelve.open(ipasnfilecache, flag='n', protocol=2)
                    s['asnip'] = asnip
                    s['ipasn4'] = to_dict(ipasn4)
                    s['ipasn6'] = to_dict(ipasn6)
                    s.close()

                except BaseException as err:
                    log_err('Cannot Shelve ASN entries to \"' + ipasnfilecache + '\" - ' + str(err))

        log_info(str(len(asnip)) + ' ASNs')
        log_info(str(len(ipasn4)) + ' ASN IPv4 Networks')
        log_info(str(len(ipasn6)) + ' ASN IPv6 Networks')


    # Get top-level-domains
    if tldurl and tldfile:
        tldlist.clear()
        age = file_exist(tldoutfile)

        if not age or age > maxlistage:
            log_info('\nDownloading IANA TLD list from \"' + tldurl + '\" to \"' + tldfile + '\"')
            r = requests.get(tldurl, timeout=10, headers=headers, allow_redirects=True)
            if r.status_code == 200:
                try:
                    with open(tldfile, 'w') as f:
                        f.write(r.text.encode('ascii').replace('\r', '').lower())

                except BaseException as err:
                    log_err('Unable to write to file \"' + tldfile + '\": ' + str(err))
                    tldfile = False
            else:
                log_err('Error during downloading TLDs (' + str(r.status_code) + ' - ' + str(r.reason) + ')')
                tldfile = False
        else:
            log_info('\nRe-Using IANA TLD list from \"' + tldoutfile + '\" (' + str(age) + ' Seconds < ' + str(maxlistage) + ')')
            tldfile = tldoutfile
            tldoutfile = False

        if tldfile:
            log_info('Fetching TLD list from \"' + tldfile + '\"')
            try:
                with open(tldfile, 'r') as f:
                    for line in f:
                        entry = line.strip()
                        if not (entry.startswith("#")) and not (len(entry) == 0):
                            tldlist[entry] = True

            except BaseException as err:
                log_err('Unable to read from file \"' + tldfile + '\": ' + str(err))
                tldfile = False

            tldlist = optimize_domlists(tldlist, 'TLD-Doms')

            if tldfile and tldoutfile:
                log_info('Writing TLD file \"' + tldoutfile + '\"')
                try:
                    with open(tldoutfile, 'w') as f:
                        for tld in sorted(tldlist.keys()):
                           f.write(tld + '\n')

                except BaseException as err:
                    log_err('Unable to write to file \"' + tldoutfile + '\": ' + str(err))

            if tldfile and adtldoutfile:
                age = file_exist(adtldoutfile)
                if not age or age > maxlistage:
                    log_info('Writing AutoDiscover-TLD file \"' + adtldoutfile + '\"')
                    try:
                        with open(adtldoutfile, 'w') as f:
                            for tld in sorted(tldlist.keys()):
                               f.write('autoconfig.' + tld + '\n')
                               f.write('autodiscover.' + tld + '\n')
                               f.write('_autodiscover._tcp.' + tld + '\n')
                               f.write('isatap.' + tld + '\n')
                               f.write('b._dns-sd.' + tld + '\n')
                               f.write('db._dns-sd.' + tld + '\n')
                               f.write('lb._dns-sd.' + tld + '\n')
                               f.write('wpad.' + tld + '\n')
                               f.write('wpad.tcp.' + tld + '\n')

                    except BaseException as err:
                        log_err('Unable to write to file \"' + adtldoutfile + '\": ' + str(err))

                else:
                    log_info('\nRe-Using AUTOCONFIG IANA TLD list from \"' + adtldoutfile + '\" (' + str(age) + ' Seconds < ' + str(maxlistage) + ')')


            if tldfile and tldfilerx:
                log_info('Writing TLD-Regex file \"' + tldfilerx + '\"')
                tldlistkeys = sorted(tldlist.keys())
                try:
                    with open(tldfilerx, 'w') as f:
                        f.write('# IANA TLD List\n')
                        f.write('# ' + tldurl + '\n')
                        f.write('/^(?!(.*\.)*(')
                        for tld in sorted(tldlistkeys)[:-1]:
                            f.write(tld + '|')
                        f.write(sorted(tldlistkeys)[-1] + ')$).*$/=NXDOMAIN\n')

                except BaseException as err:
                    log_err('Unable to write to file \"' + tldfilerx + '\": ' + str(err))

            if tldfile and dnsmasqtldfile:
                try:
                    with open(dnsmasqtldfile, 'w') as f:
                        f.write('# DNSMASQ TLD Filter List\n')
                        f.write('# ' + tldurl + '\n')
                        f.write('# Generate NXDOMAIN when tld does not exist\n')
                        f.write('address=/#/\n')
                        for tld in sorted(tldlist.keys())[:-1]:
                            f.write('server=/' + tld + '/#\n')
                        f.write('# EOF')

                except BaseException as err:
                    log_err('Unable to write to file \"' + tldfilerx + '\": ' + str(err))


            if tldfile:
                if rfc2606:
                    tldlist['example'] = True
                    tldlist['invalid'] = True
                    tldlist['localhost'] = True
                    tldlist['test'] = True

                if notinternet:
                    tldlist['onion'] = True

                if intranet:
                    tldlist['corp'] = True
                    tldlist['home'] = True
                    tldlist['host'] = True
                    tldlist['lan'] = True
                    tldlist['local'] = True
                    tldlist['localdomain'] = True
                    tldlist['mail'] = True
                    tldlist['router'] = True
                    tldlist['workgroup'] = True

            log_info('fetched ' + str(len(tldlist)) +  ' TLDs')

    if top1mfile:
        log_info('\nFetching Top-1M list from \"' + top1mfile + '\"')

        top1mlist.clear()

        try:
            with open(top1mfile, 'r') as f:
                for line in f:
                    entry = line.strip().strip('.')
                    if (not entry.startswith("#")) and (len(entry) > 0) and (isdomain.match(entry)):
                        #top1mlist[entry] = entry
                        top1mlist.add(entry)

            # Make sure rev-ips will not be lost
            top1mlist.add('in-addr.arpa')
            top1mlist.add('ip6.arpa')

        except BaseException as err:
            log_err('Unable to read from file \"' + top1mfile + '\": ' + str(err))
            tldfile = False

        log_info('fetched ' + str(len(top1mlist)) +  ' domains')
        #top1mlist = optimize_domlists(top1mlist, "Top1M") # TOO SLOW!

    #if replacefile:
    #    log_info('\nFetching replace-regexes from \"' + replacefile + '\"')
    #    try:
    #        with open(replacefile, 'r') as f:
    #            for line in f:
    #                entry = line.strip()
    #                if not (entry.startswith("#")) and not (len(entry) == 0):
    #                    elements = entry.split('\t')
    #                    if len(elements) > 1:
    #                        replacelist[elements[0]] = elements[1]
    #                        if (debug >= 2): log_info('Fetching replace-regex \"' + elements[0] + '\" -> \"' + elements[1] +'\"')
    #                    else:
    #                        log_err('Invalid replace-regex entry: \"' + entry + '\"')
    #
    #    except BaseException as err:
    #        log_err('Unable to read from file \"' + replacefile + '\": ' + str(err))
    #        tldfile = False

    if fileregexlist:
        log_info('\nFetching list-regexes from \"' + fileregexlist + '\"')
        try:
            with open(fileregexlist, 'r') as f:
                for line in f:
                    entry = line.strip()
                    if not (entry.startswith("#")) and not (len(entry) == 0):
                        elements = entry.split('\t')
                        if len(elements) > 1:
                            name = elements[0].strip().upper()
                            if (debug >= 3): log_info('Fetching file-regex \"@' + name + '\"')
                            fileregex[name] = elements[1]
                        else:
                            log_err('Invalid list-regex entry: \"' + entry + '\"')

        except BaseException as err:
            log_err('Unable to read from file \"' + fileregexlist + '\": ' + str(err))
            tldfile = False

    # Read Lists
    readblack = True
    readwhite = True

    age = file_exist(whitesave)
    if age and age < maxlistage:
        log_info('Using White-Savelist, not expired yet (' + str(age) + '/' + str(maxlistage) + ')')
        read_lists('saved-whitelist', whitesave, rwhitelist, cwhitelist4, cwhitelist6, whitelist, asnwhitelist, safewhitelist, safeunwhitelist, True, 'white', False, False, False, False, False, False)
        readwhite = False

    age = file_exist(blacksave)
    if age and age < maxlistage:
        log_info('Using Black-Savelist, not expired yet (' + str(age) + '/' + str(maxlistage) + ')')
        read_lists('saved-blacklist', blacksave, rblacklist, cblacklist4, cblacklist6, blacklist, asnblacklist, safeblacklist, False, True, 'black', False, False, False, False, False, False)
        readblack = False

    try:
        with open(sources, 'r') as f:
            for line in f:
                entry = line.strip().replace('\r', '')
                if not (entry.startswith("#")) and not (len(entry) == 0):
                    element = entry.split('\t')
                    if len(element) > 2:
                        listname = element[0]
                        log_info('\n----- ' + listname.upper() + ' -----')

                        maxnum = False

                        bw = element[1].lower()
                        bwtype = bw.strip('!*^(><')

                        forced = False
                        if bw.endswith('!'):
                            bw = bw.rstrip('!')
                            if (debug > 1): log_info('The ' + bwtype + 'list \"' + listname + '\" will be FORCED!')
                            forced = True

                        getasn = False
                        if bw.endswith('*'):
                            bw = bw.rstrip('*')
                            if (debug > 1): log_info('Retrieving ASNs for ' + bwtype + 'list \"' + listname + '\"')
                            getasn = True

                        topcheck = False
                        if bw.endswith('^'):
                            bw = bw.rstrip('^')
                            if (debug > 1): log_info('Only use TOP domain of ' + bwtype + 'list \"' + listname + '\"')
                            topcheck = True

                        stripwww = True
                        if bw.endswith('('):
                            bw = bw.rstrip('(')
                            if (debug > 1): log_info('Do not strip WWW labels from ' + bwtype + 'list \"' + listname + '\"')
                            stripwww = False

                        anytld = False
                        notld = False
                        if bw.endswith('>'):
                            bw = bw.rstrip('>')
                            if (debug > 1): log_info('Accept any TLD ' + bwtype + 'list \"' + listname + '\"')
                            anytld = True

                        revdom = False
                        if bw.endswith('<'):
                            bw = bw.rstrip('<')
                            if (debug > 1): log_info('Reverse Domains will be generated for ' + bwtype + 'list \"' + listname + '\"')
                            revdom = True

                        bw = bwtype

                        if (debug > 1): log_info('Type: ' + bw + 'list')

                        if (bw == 'black' and readblack) or (bw == 'white' and readwhite) or (bw == 'exclude' and (readwhite or readblack)):
                            source = element[2]
                            downloadfile = False
                            listfile = False
                            force = False
                            url = False

                            if source.find('^') > 0:
                                maxnum = int(source.split('^')[1])
                                source = source.split('^')[0]
                                if (debug >= 2): log_info('Maximum number entries to fetch: ' + str(maxnum))

                            if source.startswith('http://') or source.startswith('https://'):
                                notld = True
                                url = source
                                dom = url.split('/')[2]
                                whitelist[dom] = 'Source'
                                if (debug >= 2): log_info('Source for \"' + listname + '\" is a ' + bw + 'list URL: \"' + url + '\" (Whitelist: ' + dom + ')')
                            else:
                                if (debug >= 2): log_info('Source for \"' + listname + '\" is a ' + bw + 'list FILE: \"' + source + '\"')
                                if source.endswith('!'):
                                    source = source.rstrip('!')
                                elif workdir:
                                    source = workdir + "/" + source.split('/')[-1]

                            if source:
                                if len(element) > 3:
                                    listfile = element[3]
                                else:
                                    listfile = workdir + '/' + id.strip('.').lower() + ".list"

                                if workdir:
                                    listfile = workdir + '/' + listfile.split('/')[-1]

                                if len(element) > 4:
                                    filettl = int(element[4])
                                else:
                                    filettl = maxlistage

                                fregex = defaultfregex
                                if len(element) > 5:
                                    r = element[5]
                                    if r.startswith('@'):
                                        fregex = r.lstrip('@').upper().strip()
                                    elif r.find('(?P<') == -1:
                                        log_err('Regex \"' + r + '\" does not contain placeholder (e.g: \"(?P< ... )\")')
                                    else:
                                        fregex = r

                                    if fregex.endswith('!'):
                                        fregex = fregex.rstrip('!')
                                        negate = True
                                    else:
                                        negate = False


                                    if (debug >= 2): log_info(listname + ': Using regex(es): ' + fregex)

                                exclude = regex.compile(defaultexclude, regex.I)
                                if len(element) > 6:
                                    r = element[6]
                                    if r.startswith('@'):
                                        r = r.split('@')[1].upper().strip()
                                        if r in fileregex:
                                            exclude = regex.compile(fileregex[r], regex.I)
                                            if (debug >= 3): log_info('Using \"@' + r + '\" exclude regex/filter for \"' + listname + '\" (' + r + ')')
                                        else:
                                            log_err('Regex \"@' + r + '\" does not exist in \"' + fileregexlist + '\" using default \"' + defaultexclude +'\"')
                                    else:
                                        exclude = regex.compile(r, regex.I)

                                    if (debug >= 2): log_info(listname + ': Using exclude regex(es): ' + r)

                                if url:
                                    age = file_exist(listfile)
                                    if not age or age > filettl or force:
                                        downloadfile = listfile + '.download'
                                        log_info('Downloading \"' + listname + '\" from \"' + url + '\" to \"' + downloadfile + '\"')
                                        try:
                                            r = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
                                            if r.status_code == 200:
                                                try:
                                                    with open(downloadfile, 'w') as f:
                                                        f.write(r.text.encode('ascii', 'ignore').replace('\r', '').strip().lower())

                                                except BaseException as err:
                                                    log_err('Unable to write to file \"' + downloadfile + '\": ' + str(err))

                                            else:
                                                log_err('Error during downloading from \"' + url + '\" (' + str(r.status_code) + ' - ' + str(r.reason) + ')')

                                        except BaseException as err:
                                            log_err('Error downloading from \"' + url + '\" - ' + str(err))

                                    else:
                                        log_info('Skipped download \"' + listname + '\" previous list \"' + listfile + '\" is only ' + str(age) + ' seconds old')
                                        source = listfile

                                if url and downloadfile:
                                    sourcefile = downloadfile
                                else:
                                    sourcefile = source

                                if file_exist(sourcefile) >= 0:
                                    if sourcefile != listfile:
                                        seen = set()
                                        rxcount = dict()
                                        try:
                                            log_info('Creating \"' + listname + '\" file \"' + listfile + '\" from \"' + sourcefile + '\"')
                                            with open(sourcefile, 'r') as f:
                                                try:
                                                    with open(listfile, 'w') as g:
                                                        for line in f:
                                                            line = line.replace('\r', '').lower().strip()
                                                            if line and len(line) > 0:
                                                                for rx in regex.split('\s*,\s*', fregex):
                                                                    if rx in fileregex:
                                                                        frx = fileregex[rx]
                                                                        matchentry = regex.match(frx, line, regex.I)
                                                                        if matchentry:
                                                                            for placeholder in ['asn', 'host', 'domain', 'entry', 'ip', 'line', 'regex', 'default1', 'default2', 'default3']:
                                                                                try:
                                                                                    entry = matchentry.group(placeholder)
                                                                                except:
                                                                                    entry = False

                                                                                if entry and len(entry) > 0 and (entry.upper() not in seen):
                                                                                    if rx in rxcount:
                                                                                        rxcount[rx] += 1
                                                                                    else:
                                                                                        rxcount[rx] = 1

                                                                                    seen.add(entry.upper())

                                                                                    if not exclude.match(entry):
                                                                                        # !!! To do: use placholder to pre-process/validate/error-check type of entry via regex
                                                                                        g.write(entry.rstrip('!'))
                                                                                        if forced:
                                                                                            g.write('!')
                                                                                        if bw != 'exclude':
                                                                                            g.write('\t' + placeholder + ' : ' + frx + '\t (' + line + ')')
                                                                                        g.write('\n')
                                                                                    else:
                                                                                        if (debug >= 3): log_info(listname + ': Skipping excluded entry \"' + line + '\" (' + entry + ')')
                                                                                        break

                                                                        else:
                                                                            if (debug >= 3): log_info(listname + ': Skipping non-matched line \"' + line + '\" - \"' + frx +'\"')


                                                except BaseException as err:
                                                    log_err('Unable to write to file \"' + listfile + '\" - ' + str(err))


                                        except BaseException as err:
                                            log_err('Unable to read source-file \"' + sourcefile + ' - ' + str(err))


                                        for rx in rxcount.keys():
                                            log_info('Regex \"' + rx + '\" resulted in ' + str(rxcount[rx]) + ' entries')


                                    else:
                                        log_info('Skipped processing of \"' + listname + '\", source-file \"' + sourcefile + '\" same as list-file')

                                else:
                                    log_info('Skipped \"' + listname + '\", source-file \"' + sourcefile + '\" does not exist')


                            if file_exist(listfile) >= 0:
                                skippedentries = dict()

                                if bw == 'black':
                                    skippedentries = read_lists(listname, listfile, rblacklist, cblacklist4, cblacklist6, blacklist, asnblacklist, safeblacklist, False, force, bw, getasn, maxnum, topcheck, stripwww, notld, revdom)
                                elif bw == 'white':
                                    read_lists(listname, listfile, rwhitelist, cwhitelist4, cwhitelist6, whitelist, asnwhitelist, safewhitelist, safeunwhitelist, force, bw, getasn, maxnum, topcheck, stripwww, notld, revdom)
                                elif bw == 'exclude':
                                    excount = 0
                                    log_info('Reading EXCLUDE file \"' + listfile + '\"')
                                    try:
                                        with open(listfile, 'r') as f:
                                            for line in f:
                                                elements = line.strip().replace('\r', '').split('\t')
                                                entry = elements[0]
                                                if (len(entry) > 0) and isdomain.match(entry):
                                                    if len(elements)>1:
                                                        action = elements[1].lower().rstrip('!')
                                                    else:
                                                        action = 'exclude'

                                                    excludelist[entry] = action
                                                    excount += 1

                                        log_info('Fetched ' + str(excount) + ' exclude entries from \"' + listfile + '\" (' + listname + ')')

                                    except BaseException as err:
                                        log_err('Unable to read list-file \"' + listfile + '\" - ' + str(err))

                                else:
                                    log_err('Unknow type \"' + bw + '\" for file \"' + listfile + '\"')


                                if skippedentries:
                                    newinvalidskipped = dict(invalidskipped)
                                    newinvalidskipped.update(skippedentries)
                                    invalidskipped = dict(newinvalidskipped)
                                    newinvalidskipped.clear()

                            else:
                                log_err('Cannot open \"' + listfile + '\"')
                        else:
                            log_info('Skipping ' + bw + 'list \"' + listname + '\", using savelist')
                    else:
                        log_err('Not enough arguments: \"' + entry + '\"')

    except BaseException as err:
        log_err('Unable to open file \"' + sources + '\" - ' + str(err))


    log_info('\n----- OPTIMIZING PHASE -----')


    # Make sure topdoms is empty
    topdoms = dict()


    # Excluding domains, first thing to do on "dirty" lists
    excludelist = optimize_domlists(excludelist, 'ExcludeDoms')
    whitelist, _ = exclude_domlist(whitelist, excludelist, 'WhiteDoms')
    blacklist, _ = exclude_domlist(blacklist, excludelist, 'BlackDoms')
        
    # Top-X check, remove entries not in Top-X
    # whitelist = top_check(whitelist, 'Whitelist', 0)
    # blacklist = top_check(blacklist, 'Blacklist', 0)


    #if revdom:
    #    log_info('\n----- ADDING REVERSE ZONES FROM CIDRs ----')
    #    for cidr in cblacklist4.keys():
    #        for arpadom in rev_ip(cidr):
    #            blacklist[arpadom] = 'REV: ' + str(cidr)
    #
    #    for cidr in cblacklist6.keys():
    #        for arpadom in rev_ip(cidr):
    #            blacklist[arpadom] = 'REV: ' + str(cidr)
    #
    #    for cidr in cwhitelist4.keys():
    #        for arpadom in rev_ip(cidr):
    #            whitelist[arpadom] = 'REV: ' + str(cidr)
    #
    #    for cidr in cwhitelist6.keys():
    #        for arpadom in rev_ip(cidr):
    #            whitelist[arpadom] = 'REV: ' + str(cidr)


    # Save hosts/domains as-is
    if readblack or readwhite:
        hosts_save()

        plain_save('white', False)
        plain_save('black', False)


    # Optimize/Aggregate white domain lists (remove sub-domains is parent exists and entries matchin regex)
    if readwhite:
        whitelist = optimize_domlists(whitelist, 'WhiteDoms')
        safewhitelist = optimize_domlists(safewhitelist, 'SafeWhiteDoms')
        cwhitelist4 = aggregate_ip(cwhitelist4, 'WhiteIP4s', 32)
        cwhitelist6 = aggregate_ip(cwhitelist6, 'WhiteIP6s', 128)

    # Optimize/Aggregate black domain lists (remove sub-domains is parent exists and entries matchin regex)
    if readblack:
        blacklist = optimize_domlists(blacklist, 'BlackDoms')
        safeblacklist = optimize_domlists(safeblacklist, 'SafeBlackDoms')
        cblacklist4 = aggregate_ip(cblacklist4, 'BlackIP4s', 32)
        cblacklist6 = aggregate_ip(cblacklist6, 'BlackIP6s', 128)


    # Remove whitelisted entries from blacklist
    if readblack or readwhite:
        blacklist = uncomplicate_lists(whitelist, rwhitelist, blacklist, safeblacklist)
        cblacklist4 = uncomplicate_ip_lists(cwhitelist4, cblacklist4, 'IPv4', 32)
        cblacklist6 = uncomplicate_ip_lists(cwhitelist6, cblacklist6, 'IPv6', 128)

        dnsmasq_save()
        unbound_save()

        #whitelist = unwhite_domain(whitelist, blacklist, False)

        cwhitelist4 = unwhite_ip(cwhitelist4, cblacklist4, 'WhiteIP4s', 32)
        cwhitelist6 = unwhite_ip(cwhitelist6, cblacklist6, 'WhiteIP6s', 128)

        #whitelist = is_active(whitelist, 'WhiteList')
        #blacklist = is_active(blacklist, 'BlackList')

        #whitelist.update(safewhitelist)
        #blacklist.update(safeblacklist)

        whitelist, _ = exclude_domlist(whitelist, excludelist, 'WhiteDoms')
        blacklist, _ = exclude_domlist(blacklist, excludelist, 'BlackDoms')

        topdoms = make_top(blacklist, 'BlackList')

        rpz_save('white', False, False)
        rpz_save('black', False, False)
        rpz_save('white', False, True)
        rpz_save('black', False, True)

        ls_save(sourcename.title(), 'black', False)
        ls_save(sourcename.title(), 'black', True)

        rpz_save('white', True, False)
        rpz_save('white', True, True)
        rpz_save('black', True, False)
        rpz_save('black', True, True)

        knot_save()

        routedns_save(False)

        coredns_save(False)

        whitelist = unreg_lists(whitelist, rwhitelist, safewhitelist, 'WhiteDoms')
        blacklist = unreg_lists(blacklist, rblacklist, safeblacklist, 'BlackDoms')

        topdoms = make_top(blacklist, 'BlackList Optimized')

        adblock_save()
        dnsmasq_regex_save()
        squid_save()

        routedns_save(True)

        coredns_save(True)

        deugniets_save('white', whitelist, cwhitelist4, cwhitelist6, rwhitelist)
        deugniets_save('black', blacklist, cblacklist4, cblacklist6, rblacklist)

        plain_save('white', True)
        plain_save('black', True)

        # Save processed list for distribution
        log_info('\n----- SAVE LISTS -----')
        write_out(whitesave, blacksave, False)

    log_info('\n----- GRAND TOTAL -----')

    # Reporting
    regexcount = str(len(rwhitelist)/3)
    ipcount = str(len(cwhitelist4) + len(cwhitelist6))
    domaincount = str(len(whitelist))
    asncount = str(len(asnwhitelist))
    log_info('WhiteList Totals: ' + regexcount + ' REGEXES, ' + ipcount + ' IPs/CIDRs, ' + domaincount + ' DOMAINS and ' + asncount + ' ASNs')

    regexcount = str(len(rblacklist)/3)
    ipcount = str(len(cblacklist4) + len(cblacklist6))
    domaincount = str(len(blacklist))
    asncount = str(len(asnblacklist))
    log_info('BlackList Totals: ' + regexcount + ' REGEXES, ' + ipcount + ' IPs/CIDRs, ' + domaincount + ' DOMAINS and ' + asncount + ' ASNs')

    log_info('\n----- ACCOMPLIST Finished -----\n')

    sys.exit(0)

##########################################################################################
# <EOF>
