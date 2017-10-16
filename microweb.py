
import Queue
import socket
import threading


class HTTPWorker(threading.Thread):

    def __init__(self, connection_queue):

        threading.Thread.__init__(self)
        self.daemon = True  # daemonise so it dies with main
        self.connq = connection_queue

    def run(self):

        while True:
            connection = self.connq.get()
            request = connection.recv(1024)
            print request

            http_response = """
HTTP/1.1 200 OK

Hello, World!
"""
            connection.sendall(http_response)
            connection.close()


if __name__ == '__main__':

    HOST, PORT = '', 8080
    connection_queue = Queue.Queue()

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((HOST, PORT))
    listen_socket.listen(1)

    print "Serving on port {}".format(PORT)

    http_worker = HTTPWorker(connection_queue)
    http_worker.start()

    while True:
        client_connection, client_address = listen_socket.accept()
        connection_queue.put(client_connection)
