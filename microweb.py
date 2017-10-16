#! /usr/bin/python2.7

import argparse
import logging
import logging.handlers
import Queue
import socket
import threading


class HTTPRequest(object):
    def __init__(self, request):
        lines = request.splitlines()
        method, request_uri, http_version = lines[0].split()
        del lines[0]

        self.method = method
        self.request_uri = request_uri
        self.http_version = http_version

        self.headers = {}

        for line in lines:
            try:
                _header, _value = line.split(' ', 1)
            except ValueError:
                pass  # empty header
            else:
                self.headers[_header] = _value

    def __str__(self):
        return "Method: {} Request URI: {} HTTP Version: {} {}".format(self.method,
                                                                       self.request_uri,
                                                                       self.http_version,
                                                                       ' '.join(["Header {}: {}".format(x, self.headers[x]) for x in self.headers]))


class HTTPResponse(object):
    def __init__(self, http_version):
        self.http_version = http_version
        self.response_code = 200
        self.response_message = "OK"
        self.body = ""

    def __str__(self):
        return "{} {} {}\n\n{}".format(self.http_version,
                                       self.response_code,
                                       self.response_message,
                                       self.body)


class HTTPWorker(threading.Thread):

    def __init__(self, connection_queue, log):

        threading.Thread.__init__(self)
        self.daemon = True  # daemonise so it dies with main
        self.connq = connection_queue
        self.log = log
        self.log.debug("%s Awaiting connections", self.name)

    def run(self):

        while True:
            connection = self.connq.get()
            request = HTTPRequest(connection.recv(1024))
            log.info("%s %s %s %s",
                     self.name,
                     request.method,
                     request.request_uri,
                     request.http_version)
            log.debug(str(request))

            response = HTTPResponse(request.http_version)
            response.body = "Hello, World!"

            connection.sendall(str(response))
            connection.close()


if __name__ == '__main__':

    connection_queue = Queue.Queue()

    parser = argparse.ArgumentParser(description="Micro Web", add_help=False)
    parser.add_argument('--help', action='help', help='show this help message and exit')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help="Don't display log messages")
    parser.add_argument('--debug', action='store_true', default=False, help="Enable debug logging")
    parser.add_argument('-h', '--host', type=str, default='', help="Host to connect socket to. Default ''.")
    parser.add_argument('-p', '--port', type=int, default=8080, help="Port to connect socket to. Default 8080.")
    parser.add_argument('-t', '--threads', type=int, default=2, help="Processing threads to start. Default 2.")
    options = parser.parse_args()

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
        _worker = HTTPWorker(connection_queue, log)
        _worker.start()
        http_workers.append(_worker)

    while True:
        client_connection, client_address = listen_socket.accept()
        connection_queue.put(client_connection)
