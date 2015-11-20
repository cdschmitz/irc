#!/usr/bin/env python
"""
Chris Schmitz
CS 494
"""
import argparse
import select
import socket
import sys

BUF_SIZE = 4096
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 12000
MESSAGE_END = '\r\n'
SOCKET_TIMEOUT = 3


class IRCClient(object):
    def __init__(self, host, port):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect((host, port))
        except socket.error as e:
            sys.stderr.write('Failed to connect socket: {}\n'.format(e))
            sys.exit(1)

        client_socket.settimeout(SOCKET_TIMEOUT)

        self.client_socket = client_socket
        self.channels = set()
        self.current_channel = None
        self.input_sources = [client_socket, sys.stdin]
        self.socket_buffer = ''

    def _show_prompt(self):
        sys.stdout.write('sup> ')
        sys.stdout.flush()

    def connect(self):
        try:
            while True:
                ready_sources, _, _ = select.select(self.input_sources, [], [])
                for ready_source in ready_sources:
                    if ready_source == self.client_socket:
                        input_chunk = self.client_socket.recv(BUF_SIZE)
                        if not input_chunk:
                            sys.exit('Connection terminated by server')

                        socket_input = ''.join([self.socket_buffer, input_chunk])
                        messages = socket_input.split(MESSAGE_END)
                        self.socket_buffer = messages.pop()
                        for message in messages:
                            print message

                        self._show_prompt()
                    elif ready_source == sys.stdin:
                        input_chunk = sys.stdin.readline().strip()
                        if input_chunk:
                            message = ''.join([input_chunk, MESSAGE_END])
                            self.client_socket.send(message)
                        self._show_prompt()
        finally:
            self.client_socket.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run IRC client')
    parser.add_argument('-n', '--host',
                        help='Hostname of the running IRC server',
                        default=DEFAULT_HOST)
    parser.add_argument('-p', '--port',
                        help='Port number of the running IRC server',
                        default=DEFAULT_PORT,
                        type=int)
    args = parser.parse_args()

    client = IRCClient(args.host, args.port)
    client.connect()
