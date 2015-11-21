#!/usr/bin/env python
"""
Chris Schmitz
CS 494

Server side of IRC application. Uses select rather than multithreading to
simultaneously monitor multiple client sockets.
"""
import argparse
import logging
import re
import select
import socket
import sys

BUF_SIZE = 4096
DEFAULT_PORT = 12000
MAX_CONNECTIONS = 8

MESSAGE_END = '\r\n'
MESSAGE = 'MSG'
REPLY = 'RPL'

# Mesage codes
PUBLIC = 200
PRIVATE = 201

# Standard reply codes
NICK_CHANGE_ACCEPTED = 301
CHANNEL_JOINED = 302
CHANNEL_LEFT = 303
CHANNEL_LIST = 304
USERS_IN_CHANNEL = 305

# Error codes
UNRECOGNIZED_CLIENT_MESSAGE = 400
INVALID_NICK_FORMAT = 401
USERNAME_ALREADY_CURRENT = 402
USERNAME_UNAVAILABLE = 403
INVALID_CHANNEL_FORMAT = 404
CHANNEL_ALREADY_JOINED = 405
CHANNEL_NOT_JOINED = 406
NONEXISTENT_CHANNEL = 407
NONEXISTENT_USER = 408
EMPTY_MESSAGE = 409

CHANNEL_RE = re.compile(r'^#[_a-zA-Z]\w{0,30}$')
NICK_RE = re.compile(r'^[_a-zA-Z]\w{0,31}$')
PRIVATE_MESSAGE_RE = re.compile(r'^(?P<username>[_a-zA-Z]\w{0,31})'
                                ' (?P<message>.*)$')
PUBLIC_MESSAGE_RE = re.compile(r'^(?P<channel>#[_a-zA-Z]\w{0,30})'
                               ' (?P<message>.*)$')
VALID_CLIENT_MESSAGE_RE = re.compile(r'^\s*(?P<command>[A-Z]+)(?: |$)')


class IRCServer(object):
    def __init__(self, port):
        """
        Bind the server socket and initialize global state
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_socket.bind(('', port))
        except socket.error as e:
            sys.stderr.write('Failed to bind socket: {}\n'.format(e))
            sys.exit(1)

        server_socket.listen(MAX_CONNECTIONS)
        logging.info('IRC Server running on port {}...'.format(port))

        self.server_socket = server_socket
        self.client_connections = {}
        self.user_index = 1

        self.handlers = {
            'JOIN': self._process_join_command,
            'LEAVE': self._process_leave_command,
            'LIST': self._process_list_command,
            'MSG': self._process_public_message,
            'NICK': self._process_nick_command,
            'PRVMSG': self._process_private_message,
            'QUIT': self._process_quit_command
        }

    @property
    def _active_channels(self):
        channel_sets = [state['channels']
                        for state in self.client_connections.values()]
        return reduce(lambda a, b: a.union(b), channel_sets, set())

    @property
    def _active_usernames(self):
        return set(state['username']
                   for state in self.client_connections.values())

    def _close_client_connection(self, client_socket):
        """
        Remove the client from the list of connections and close the socket
        """
        conn_state = str(client_socket.getpeername())
        del self.client_connections[client_socket]
        client_socket.close()
        logging.debug('Client terminated connection: {}'.format(conn_state))

    def _handle_client_input(self, client_socket, input_chunk):
        """
        Parse the raw client input and determine the appropriate action.
        The chunk is appended to the input buffer, and all complete messages
        are acted on (messages terminated by CRLF). If the message matches an
        accepted format, a handler for the matched command is called.
        Otherwise a reply is returned to the client that their message was
        invalid.
        """
        client_state = self.client_connections[client_socket]
        input_buffer = ''.join([client_state['input_buffer'], input_chunk])
        messages = input_buffer.split(MESSAGE_END)
        client_state['input_buffer'] = messages.pop()
        logging.debug('Input Buffer: {}'.format(client_state['input_buffer']))

        for message in messages:
            logging.debug('Received message: {}'.format(message))

            command_match = VALID_CLIENT_MESSAGE_RE.match(message)
            if command_match:
                command = command_match.groupdict()['command']
                if command in self.handlers:
                    match_text = command_match.group()
                    handler = self.handlers[command]
                    handler(client_socket, message[len(match_text):])
                    continue
            self._process_invalid_message(client_socket, message)

    def _initialize_client_connection(self):
        """
        Set up state info for newly connected client
        """
        connection, addr = self.server_socket.accept()
        client_state = {
            'channels': set(),
            'input_buffer': '',
            'username': 'user{}'.format(self.user_index)
        }
        self.client_connections[connection] = client_state
        self.user_index += 1
        logging.debug('Created new connection: {}'.format(str(client_state)))

    def _process_invalid_message(self, client_socket, message):
        """
        Server does not recognize the format of the client message.
        Respond with an error.
        """
        logging.debug('Unrecognized message: {}'.format(message))
        return self._send_reply(client_socket, UNRECOGNIZED_CLIENT_MESSAGE)

    def _process_join_command(self, client_socket, channel):
        """
        Handle a JOIN command from a client.
        Error responses:
          - Invalid channel format
          - Channel already joined
        """
        logging.debug("JOIN: '{}'".format(channel))

        if not CHANNEL_RE.match(channel):
            return self._send_reply(client_socket, INVALID_CHANNEL_FORMAT)

        client_state = self.client_connections[client_socket]
        joined_channels = client_state['channels']
        if channel in joined_channels:
            return self._send_reply(client_socket, CHANNEL_ALREADY_JOINED)

        client_state['channels'].add(channel)
        self.client_connections[client_socket] = client_state
        return self._send_reply(client_socket, CHANNEL_JOINED, channel)

    def _process_leave_command(self, client_socket, channel):
        """
        Handle a LEAVE command from a client.
        Error responses:
          - Invalid channel format
          - Channel not currently joined
        """
        logging.debug("LEAVE: '{}'".format(channel))

        if not CHANNEL_RE.match(channel):
            return self._send_reply(client_socket, INVALID_CHANNEL_FORMAT)

        client_state = self.client_connections[client_socket]
        joined_channels = client_state['channels']
        if channel not in joined_channels:
            return self._send_reply(client_socket, CHANNEL_NOT_JOINED)

        client_state['channels'].remove(channel)
        self.client_connections[client_socket] = client_state
        return self._send_reply(client_socket, CHANNEL_LEFT, channel)

    def _process_list_command(self, client_socket, channel):
        """
        Handle a LIST command from a client.
        If no channel argument is provided, the server responds with a list of
        active channels. If the channel is present, respond with the usernames
        of clients in the channel.
        Error responses:
          - Invalid channel format
          - Attempt to list channel that does not exist
        """
        logging.debug("LIST: '{}'".format(channel))

        if not channel:
            return self._send_reply(client_socket, CHANNEL_LIST,
                                    *self._active_channels)

        if not CHANNEL_RE.match(channel):
            return self._send_reply(client_socket, INVALID_CHANNEL_FORMAT)

        usernames_in_channel = set(state['username']
                                   for state in
                                   self.client_connections.values()
                                   if channel in state['channels'])
        return self._send_reply(client_socket, USERS_IN_CHANNEL,
                                channel, *usernames_in_channel)

    def _process_nick_command(self, client_socket, nick):
        """
        Handle a NICK command from a client requesting to change username.
        Error responses sent for:
          - Invalid nick format
          - Current nick already matches requested nick
          - A different user has already been given the requested nick
        """
        logging.debug("NICK: '{}'".format(nick))

        if not NICK_RE.match(nick):
            return self._send_reply(client_socket, INVALID_NICK_FORMAT)

        client_state = self.client_connections[client_socket]
        current_username = client_state['username']
        if nick == current_username:
            return self._send_reply(client_socket, USERNAME_ALREADY_CURRENT)

        if nick in self._active_usernames:
            return self._send_reply(client_socket, USERNAME_UNAVAILABLE)

        client_state['username'] = nick
        self.client_connections[client_socket] = client_state
        return self._send_reply(client_socket, NICK_CHANGE_ACCEPTED, nick)

    def _process_private_message(self, client_socket, message_args):
        """
        Handle a PRVMSG command from a client sending a message directly
        to another.
        Error responses sent for:
          - Unrecognized private message args, the receiving username must be
            present
          - Specified recipient doesnt exist
        """
        logging.debug("PRVMSG: '{}'".format(message_args))

        message_match = PRIVATE_MESSAGE_RE.match(message_args)
        if not message_match:
            return self._send_reply(client_socket, UNRECOGNIZED_CLIENT_MESSAGE)

        match_dict = message_match.groupdict()
        receiving_username = match_dict['username']
        message = match_dict['message']
        if receiving_username not in self._active_usernames:
            return self._send_reply(client_socket, NONEXISTENT_USER)

        sending_username = self.client_connections[client_socket]['username']
        receiving_sockets = set(receiving_socket for receiving_socket, state in
                                self.client_connections.iteritems()
                                if receiving_username == state['username'])
        for client_socket in receiving_sockets:
            self._send_message(client_socket, PRIVATE,
                               sending_username, message)

    def _process_public_message(self, client_socket, message_args):
        """
        Handle a MSG command from a client sending a public message to a
        channel.
        Error responses sent for:
          - Unrecognized public message args, the receiving channel must be
            present
          - Specified channel doesnt exist
        """
        logging.debug("MSG: '{}'".format(message_args))

        message_match = PUBLIC_MESSAGE_RE.match(message_args)
        if not message_match:
            return self._send_reply(client_socket, UNRECOGNIZED_CLIENT_MESSAGE)

        match_dict = message_match.groupdict()
        channel = match_dict['channel']
        message = match_dict['message']
        if channel not in self._active_channels:
            return self._send_reply(client_socket, NONEXISTENT_CHANNEL)

        sending_username = self.client_connections[client_socket]['username']
        receiving_sockets = set(receiving_socket for receiving_socket, state in
                                self.client_connections.iteritems()
                                if channel in state['channels'])
        for receiving_socket in receiving_sockets:
            self._send_message(receiving_socket, PUBLIC,
                               sending_username, channel, message)

    def _process_quit_command(self, client_socket, _):
        """
        QUIT command detected by client, no further processing needed
        """
        logging.debug("Received QUIT")
        self._close_client_connection(client_socket)

    def _send_message(self, client_socket, msg_code, *args):
        return self._send_to_client(client_socket, MESSAGE, msg_code, *args)

    def _send_reply(self, client_socket, reply_code, *args):
        return self._send_to_client(client_socket, REPLY, reply_code, *args)

    def _send_to_client(self, client_socket, message_type, code, *args):
        response = '{message_type} {code} {args}{end}'.format(
            message_type=message_type,
            code=code,
            args=' '.join(args),
            end=MESSAGE_END)
        logging.debug('Response: {}'.format(response))
        return client_socket.send(response)

    def serve_forever(self):
        """
        Run the IRC server indefinitely. Use the select library to monitor
        multiple sockets for input. Wrap the loop in a try/except in order to
        allow clients to gracefully handle a server crash.
        """
        server_socket = self.server_socket

        try:
            while True:
                all_connections = (
                    [self.server_socket] + self.client_connections.keys())
                input_sockets, _, _ = select.select(all_connections, [], [])
                for ready_socket in input_sockets:
                    if ready_socket == self.server_socket:
                        self._initialize_client_connection()
                    else:
                        chunk = ready_socket.recv(BUF_SIZE)
                        if not chunk:
                            self._close_client_connection(ready_socket)
                        else:
                            self._handle_client_input(ready_socket, chunk)
        except KeyboardInterrupt:
            pass
        finally:
            logging.info('\n\nServer shutdown: closing client connections')
            for client_socket in self.client_connections.keys():
                client_socket.close()
            server_socket.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run IRC server')
    parser.add_argument('-d', '--debug',
                        help='Add debug logging messages',
                        action='store_true')
    parser.add_argument('-p', '--port',
                        help='Port number on which the server runs',
                        default=DEFAULT_PORT,
                        type=int)
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format='%(message)s', level=log_level)
    irc = IRCServer(args.port)
    irc.serve_forever()
