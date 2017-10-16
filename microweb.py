
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

    def __str__(self):
        return "Method: {} Request URI: {} HTTP Version: {}".format(self.method,
                                                                    self.request_uri,
                                                                    self.http_version)


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

            response = HTTPResponse(request.http_version)
            response.body = "Hello, World!"

            connection.sendall(str(response))
            connection.close()


if __name__ == '__main__':

    HOST, PORT = '', 8080
    connection_queue = Queue.Queue()

    log = logging.getLogger("microweb")
    log.setLevel(logging.DEBUG)
    log_formatter = logging.Formatter('%(asctime)s %(levelname)8s %(message)s')
    log_console_handler = logging.StreamHandler()
    log_console_handler.setLevel(logging.DEBUG)
    log_console_handler.setFormatter(log_formatter)
    log.addHandler(log_console_handler)

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((HOST, PORT))
    listen_socket.listen(1)

    log.info("Serving on port %s", PORT)

    http_workers = []
    for x in range(2):
        _worker = HTTPWorker(connection_queue, log)
        _worker.start()
        http_workers.append(_worker)

    while True:
        client_connection, client_address = listen_socket.accept()
        connection_queue.put(client_connection)
