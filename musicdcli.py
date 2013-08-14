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
    parser.add_option("-r", "--request", dest = "request_type", 
                      metavar = "TYPE", help = "the type of the request. valid \values are: albums, artists and tracks")
    parser.add_option("--name", dest = "name", help = "string to search with")
    parser.add_option("--id", dest = "id", type = "int", 
                      help = "the id of the object to be requested")
    parser.add_option("--trackid", dest = "trackid", type = "int", 
                      help = "the id of the track to be requested", 
                      metavar = "TRACKID")
    parser.add_option("--artistid", dest = "artistid", type = "int", 
                      help = "the id of the artist to be requested",
                      metavar = "ARTISTID")
    parser.add_option("--albumid", dest = "albumid", type = "int", 
                      help = "the id of the album to be requested", 
                      metavar = "ALBUMID")
    parser.add_option("--artist", dest = "artist", help = "name of the artist",
                      metavar = "ARTIST")
    parser.add_option("--album", dest = "album", help = "name of the album",
                      metavar = "ALBUM")
    parser.add_option("--sort", dest = "sort", help = "sorting string",
                      metavar = "SORT")
    parser.add_option("--offset", dest = "offset", 
                      help = "amount of omitted results", metavar="OFFSET")
    parser.add_option("--limit", dest = "limit", 
                      help = "amount of results shown", metavar = "LIMIT")
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

def humanize_resp(resp):
    '''Print dict in somewhat more sensible fashion.'''
    for set in resp:
        for row in resp[set]:
            print(row)

def unbuffered_file_dump(file):
    unbuffered = os.fdopen(sys.stdout.fileno(), 'wb', 0)
    data = file.read(10000)
    while data:
        unbuffered.write(data)
        data = file.read(10000)

class Musicd:
    '''A class for interfacing with the Musicd http-interface.'''
    def __init__(self, session = None):
        self.__session = session

    def __request_server(self, session, request):
        '''Returns an urllib response object.'''
        opener = urllib.request.build_opener()
        try:
            opener.addheaders.append(('Cookie', session['cookie']))
        except KeyError:
            pass
        resp = opener.open("http://%s:%i%s" % (session['host'], 
                           session['port'], request))
        if resp.status is not 200:
            print("server returned %i, reason: %s" % (resp.status, reason))
        return resp

    def __read_json(self, resp):
        '''Read and parse json from urllib response.'''
        return json.loads(resp.read().decode('utf-8'))

    def __method_request(self, request):
        '''Make a request to the server and parse the response.'''
        return self.__read_json(self.__request_server(self.__session, request))
    
    def __get_cookie(self, resp):
        '''Return a cookie string from urllib response.'''
        return resp.getheaders()[3][1]

    def auth(self, host, port, user, password):
        '''Authenticate to the server. Set the internal session cookie.'''
        resp = self.__request_server({'host' : host, 'port' : port}, 
                                     "/auth?user=%s&password=%s" % 
                                     (user, password))
        self.__session = {'host' : host, 
                        'port' : port, 
                        'cookie' : self.__get_cookie(resp)}

    def __generic_request(self, request, valid_args, args):
        for arg in args:
            if arg in valid_args:
                if args[arg] is not None:
                    request += "%s=%s&" % (arg, str(args[arg]))
            else:
                print("invalid request parameter")
                exit(2)
        return request
    
    def albums(self, **kwargs):
        '''Return the query response in python dict.'''
        VALID_ARGS = ['albumid', 'search', 'sort', 'total', 'offset', 'limit']
        request = self.__generic_request('/albums?', VALID_ARGS, kwargs)
        return self.__method_request(request)
  
    def artists(self, **kwargs):
        '''Return the query response in python dict.'''
        VALID_ARGS = ['artistid', 'search', 'sort', 'total', 'offset', 'limit']
        request = self.__generic_request('/artists?', VALID_ARGS, kwargs)
        return self.__method_request(request)

    def tracks(self, **kwargs):
        VALID_ARGS = ['trackid', 'artistid', 'albumid', 'search', 'artist', 
                      'album', 'sort', 'total', 'offset', 'limit']
        request = self.__generic_request('/tracks?', VALID_ARGS, kwargs)
        return self.__method_request(request)

    def open(self, id):
        '''Return a file object of the mp3 stream.'''
        return self.__request_server(self.__session, '/open?id=%u' % id)

opts = cmdline_parse()
musicd = Musicd()
musicd.auth(opts.host, opts.port, opts.user, opts.password)

if opts.request_type == 'albums': 
    humanize_resp(musicd.albums(albumid=opts.id, search=opts.name, 
                                sort=opts.sort, offset=opts.offset, 
                                limit=opts.limit))
elif opts.request_type == 'artists':
    humanize_resp = (musicd.artists(artistid=opts.id, search=opts.name,
                                    sort=opts.sort, offset=opts.offset, 
                                    limit=opts.limit))
elif opts.request_type == 'tracks': 
    humanize_resp(musicd.tracks(trackid=opts.id, artistid=opts.artistid,
                  albumid=opts.albumid, search=opts.name, artist=opts.artist, 
                  album=opts.album, sort=opts.sort, offset=opts.offset, 
                  limit=opts.limit))
elif opts.request_type == 'open':
   unbuffered_file_dump(musicd.open(opts.id)) 



