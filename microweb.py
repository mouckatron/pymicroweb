#! /usr/bin/python2.7

import argparse
import logging
import logging.handlers
import os
import os.path as op
import Queue
import re
import socket
import threading

MIME_TYPES = {
    'aac': 'audio/aac',
    'abw': 'application/x-abiword',
    'arc': 'application/octet-stream',
    'avi': 'video/x-msvideo',
    'azw': 'application/vnd.amazon.ebook',
    'bin': 'application/octet-stream',
    'bz': 'application/x-bzip',
    'bz2': 'application/x-bzip2',
    'csh': 'application/x-csh',
    'css': 'text/css',
    'csv': 'text/csv',
    'doc': 'application/msword',
    'eot': 'application/vnd.ms-fontobject',
    'epub': 'application/epub+zip',
    'gif': 'image/gif',
    'htm': 'text/html',
    'html': 'text/html',
    'ico': 'image/x-icon',
    'ics': 'text/calendar',
    'jar': 'application/java-archive',
    'jpeg': 'image/jpeg',
    'jpg': 'image/jpeg',
    'js': 'application/javascript',
    'json': 'application/json',
    'mid': 'audio/midi',
    'midi': 'audio/midi',
    'mpeg': 'video/mpeg',
    'mpkg': 'application/vnd.apple.installer+xml',
    'odp': 'application/vnd.oasis.opendocument.presentation',
    'ods': 'application/vnd.oasis.opendocument.spreadsheet',
    'odt': 'application/vnd.oasis.opendocument.text',
    'oga': 'audio/ogg',
    'ogv': 'video/ogg',
    'ogx': 'application/ogg',
    'otf': 'font/otf',
    'png': 'image/png',
    'pdf': 'application/pdf',
    'ppt': 'application/vnd.ms-powerpoint',
    'rar': 'application/x-rar-compressed',
    'rtf': 'application/rtf',
    'sh': 'application/x-sh',
    'svg': 'image/svg+xml',
    'swf': 'application/x-shockwave-flash',
    'tar': 'application/x-tar',
    'tif': 'image/tiff',
    'tiff': 'image/tiff',
    'ts': 'application/typescript',
    'ttf': 'font/ttf',
    'vsd': 'application/vnd.visio',
    'wav': 'audio/x-wav',
    'weba': 'audio/webm',
    'webm': 'video/webm',
    'webp': 'image/webp',
    'woff': 'font/woff',
    'woff2': 'font/woff2',
    'xhtml': 'application/xhtml+xml',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'xml': 'application/xml',
    'xul': 'application/vnd.mozilla.xul+xml',
    'zip': 'application/zip',
    '3gp': 'video/3gpp',
    '3g2': 'video/3gpp2',
    '7z': 'application/x-7z-compressed'
}


class HTTPRequest(object):

    uri_re = re.compile('^([^?]*)\??([^#]*)#?(.*)$')
    fileext_re = re.compile('^.*\.([a-zA-Z]{2,5})$')

    def __init__(self, request):
        self._request = request
        lines = request.splitlines()
        method, request_uri, http_version = lines[0].split()
        del lines[0]

        self.method = method
        self.request_uri = request_uri
        self.http_version = http_version

        self.headers = {}
        self.uri = {'path': '', 'query': '', 'fragment': '', 'fileext': ''}
        self.parse_uri()

        for line in lines:
            try:
                _header, _value = line.split(': ', 1)
            except ValueError:
                pass  # empty header
            else:
                self.headers[_header] = _value

    def parse_uri(self):
        _parse = HTTPRequest.uri_re.match(self.request_uri)

        if _parse is None:
            return

        self.uri['path'] = _parse.group(1)
        self.uri['query'] = _parse.group(2)
        self.uri['fragment'] = _parse.group(3)
        try:
            self.uri['fileext'] = HTTPRequest.fileext_re.match(self.uri['path']).group(1)
        except AttributeError:
            pass

    def __str__(self):
        return self._request

    def debug(self):
        return "HTTPRequest Method: '{}' Request URI: '{}' Parsed URI: '{}' HTTP Version: '{}' Headers={}".format(
            self.method,
            self.request_uri,
            self.uri,
            self.http_version,
            self.headers)


class HTTPResponse(object):
    def __init__(self, http_version, http_method):
        self.http_version = http_version
        self.method = http_method
        self.response_code = 200
        self.response_message = "OK"
        self.body = ""
        self.headers = {'Server': 'pymicroweb'}

    def setbody(self, data, text=True):
        self.body = data
        if text:
            self.headers['Content-Length'] = len(self.body.encode('utf-8'))
        else:  # binary
            self.headers['Content-Length'] = len(self.body)

    def setheader(self, header, value):
        self.headers[header] = value

    def debug(self):
        return "HTTPResponse Method: '{}' Code: '{}' Message: '{}' HTTP Version: '{}' Headers={}".format(
            self.method,
            self.response_code,
            self.response_message,
            self.http_version,
            self.headers)

    def __str__(self):
        if self.method == 'HEAD':
            return "{} {} {}\n{}".format(self.http_version,
                                         self.response_code,
                                         self.response_message,
                                         "\n".join(["{}: {}".format(x, self.headers[x]) for x in self.headers]))

        return "{} {} {}\n{}\n\n{}".format(self.http_version,
                                           self.response_code,
                                           self.response_message,
                                           "\n".join(["{}: {}".format(x, self.headers[x]) for x in self.headers]),
                                           self.body)


class HTTPWorker(threading.Thread):

    def __init__(self, connection_queue, options, log):

        threading.Thread.__init__(self)
        self.daemon = True  # daemonise so it dies with main
        self.connq = connection_queue
        self.options = options
        self.wwwdir = options.www
        self.listdir = options.www_listdir
        self.log = log
        self.log.debug("%s Awaiting connections", self.name)
        self.log.debug("%s WWW dir: %s", self.name, self.wwwdir)
        self.log.debug("%s WWW List Directories: %s", self.name, ("On" if self.listdir else "Off"))

    def run(self):

        while True:
            connection = self.connq.get()
            request = HTTPRequest(connection.recv(1024))
            log.info("%s %s %s %s",
                     self.name,
                     request.method,
                     request.request_uri,
                     request.http_version)
            log.debug(request.debug())

            response = HTTPResponse(request.http_version, request.method)
            if request.method == 'GET' or request.method == 'HEAD':
                self.get(request, response)

            log.debug(response.debug())
            connection.sendall(str(response))
            connection.close()

    def directory_listing(self, request):
        html = "<html><head><title>{path}</title></head><body><h1>{path}</h1><ul>{listing}</ul></body></html>"

        _dirlist = os.listdir(op.join(self.wwwdir, request.uri['path'].lstrip('/')))
        _listing = ''.join(['<li><a href="{}/{}">{}</a></li>'.format(request.uri['path'], x, x) for x in _dirlist])

        return html.format(path=request.uri['path'], listing=_listing)

    def get(self, request, response):
        if op.isdir(op.join(self.wwwdir, request.uri['path'].lstrip('/'))):  # we have no file to check for
            log.debug("Request is a directory, checking for index.html")
            try:  # try default file
                response.setbody(open(op.join(self.wwwdir, 'index.html')).read())
            except IOError:  # if it does not exist
                if self.listdir:  # check if we can do directory listing
                    response.setbody(self.directory_listing(request))
                else:  # otherwise return a 404
                    self.log.error("File Not Found: %s", op.join(self.wwwdir, request.uri['path'].lstrip('/')))
                    response.response_code = 404
                    response.response_message = "File not found"
        else:  # we have a file name to check for
            try:
                if MIME_TYPES[request.uri['fileext']].startswith('text'):
                    response.setbody(open(op.join(self.wwwdir, request.uri['path'].lstrip('/')), 'r').read())
                else:  # binary file
                    response.setbody(open(op.join(self.wwwdir, request.uri['path'].lstrip('/')), 'rb').read(), False)
            except IOError:
                self.log.error("File Not Found: %s", op.join(self.wwwdir, request.uri['path'].lstrip('/')))
                response.response_code = 404
                response.response_message = "File not found"
            else:
                try:
                    response.setheader('Content-Type', MIME_TYPES[request.uri['fileext']])
                except KeyError:
                    self.log.error("No MIME type for %s", request.uri['fileext'])


if __name__ == '__main__':

    connection_queue = Queue.Queue()

    parser = argparse.ArgumentParser(description="Micro Web", add_help=False)
    parser.add_argument('--help', action='help', help='show this help message and exit')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help="Don't display log messages")
    parser.add_argument('--debug', action='store_true', default=False, help="Enable debug logging")
    parser.add_argument('-h', '--host', type=str, default='', help="Host to connect socket to. Default ''.")
    parser.add_argument('-p', '--port', type=int, default=8080, help="Port to connect socket to. Default 8080.")
    parser.add_argument('-t', '--threads', type=int, default=2, help="Processing threads to start. Default 2.")
    parser.add_argument('-w', '--www', type=str, default='./www', help="WWW directory for files. Default ./www.")
    parser.add_argument('--www-listdir', action='store_true', default=False, help="Show directory listings if no index.html file exists.")
    options = parser.parse_args()

    options.www = op.join(op.abspath(options.www))

    log = logging.getLogger("microweb")
    log.setLevel(logging.DEBUG if options.debug else logging.INFO)
    log_formatter = logging.Formatter('%(asctime)s %(levelname)8s %(message)s')
    log_console_handler = logging.StreamHandler()
    log_console_handler.setLevel(logging.DEBUG)
    log_console_handler.setFormatter(log_formatter)
    log.addHandler(log_console_handler)
    log.info("Level at INFO")
    log.debug("Level at DEBUG")

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((options.host, options.port))
    listen_socket.listen(1)

    log.info("Serving on port %s", options.port)

    http_workers = []
    for x in range(options.threads):
        _worker = HTTPWorker(connection_queue, options, log)
        _worker.start()
        http_workers.append(_worker)

    while True:
        client_connection, client_address = listen_socket.accept()
        connection_queue.put(client_connection)
