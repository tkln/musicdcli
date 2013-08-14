#!/usr/bin/python3.2
import json
import re
import sys
import os
import urllib.request
from http.cookiejar import CookieJar, DefaultCookiePolicy
from optparse import OptionParser

def parse_host_arg(arg):
    m = re.split(':', arg)
    ret = {'host' : m[0], 'port' : m[1]}
    return ret

def cmdline_parse():
    usage = "usage: %prog [options] host:port"
    parser = OptionParser(usage)
    parser.add_option("-u", "--user", dest = "user",
                      help = "login username", metavar = "USER")
    parser.add_option("-p", "--password", dest = "password",
                      help = "login password", metavar = "PASSWORD")
    parser.add_option("-H", "--host", dest = "host",
                      help = "server host", metavar = "HOST")
    parser.add_option("-P", "--port", dest = "port", type = "int",
                      help = "the port to connect to", metavar = "PORT")
    parser.add_option("-c", "--cookiefile", dest="cookiefile",
                      help = "the file to store session cookie in",
                      metavar = "FILE")

    (options, args) = parser.parse_args()
    try:
        if options.host == None:
            options.port = int(parse_host_arg(args[0])['port'])
            options.host = parse_host_arg(args[0])['host']
    except IndexError:
        print("Please supply a host")
        sys.exit(2)

    try:
        if options.port == None: 
            options.port = int(parse_host_arg(args[0])['port'])
    except IndexError:
        print("Please supply a port")
        sys.exit(2)

    return options

#returns a respones object
def request_server(session, request):
    opener = urllib.request.build_opener()
    try:
        opener.addheaders.append(('Cookie', session['cookie']))
    except KeyError:
        pass
    resp = opener.open("http://%s:%i%s" % (session['host'], session['port'], 
                       request))
    if resp.status is not 200:
        print("server returned %i, reason: %s" % (resp.status, reason))
    return resp

#returns a cookie string from a header
def get_cookie(resp):
    return resp.getheaders()[3][1]

#reads and parses json
def read_json(resp):
    return json.loads(resp.read().decode('utf-8'))

#authenticates to the server. returns a cookie, if successful
def auth(host, port, user, password):
    resp = request_server({'host' : host, 'port' : port}, 
                          "/auth?user=%s&password=%s" % (user, password))
    return {'host' : host, 'port' : port, 'cookie' : get_cookie(resp)}

def albums(session, albumid = None, search = None, sort = None, total = None, 
           offset = None, limit = None):
    request = "/albums?"
    if albumid:
        request += "albumid=%i&" % albumid
    if search:
        request += "search=%s&" % search
    if sort:
        request += "sort=%s&" % sort
    if total:
        request += "total=%s&" % total
    if offset:
        request += "offset=%i" % offset
    if limit:
        request += "limit=%i" % limit
    return read_json(request_server(session, request))

def humanize_resp(resp):
    for set in resp:
        for row in resp[set]:
            print(row)

opts = cmdline_parse()
session = auth(opts.host, opts.port, opts.user, opts.password)
#resp = albums(session, search = "dance")
humanize_resp(resp)

