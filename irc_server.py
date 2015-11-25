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

ERROR = 'ERROR'
MESSAGE = 'MSG'
REPLY = 'RPL'

# Message codes
PUBLIC_MESSAGE = 200
PRIVATE_MESSAGE = 201
CLIENT_JOINED_CHANNEL = 202
CLIENT_LEFT_CHANNEL = 203
NICK_CHANGED = 204

# Standard reply codes
NICK_CHANGE_ACCEPTED = 301
CHANNEL_JOINED = 302
CHANNEL_LEFT = 303
CHANNEL_LIST = 304
CHANNEL_USERS = 305
PRIVATE_MSG_DELIVERED = 306

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
USER_NOT_IN_CHANNEL = 409

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
        self.connections = {}
        self.users = {}
        self.user_index = 0

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
        channel_sets = [client_state['channels']
                        for client_state in self.connections.values()]
        return reduce(lambda a, b: a.union(b), channel_sets, set())

    def _close_client_connection(self, client_socket):
        """
        Remove the client from the list of connections and close the socket
        """
        conn_state = str(client_socket.getpeername())
        client_state = self.connections[client_socket]
        username = client_state['username']
        channels = client_state['channels']
        del self.connections[client_socket]
        del self.users[username]
        client_socket.close()

        for channel in channels:
            self._send_user_left_channel_message(username, channel)
        logging.debug('Client terminated connection: {}'.format(conn_state))

    def _get_connected_users(self, username):
        """
        Users are 'connected' if they share at least one channel with the
        specified username.  Return value is a set of usernames.
        """
        client_socket = self.users[username]
        user_channels = self.connections[client_socket]['channels']
        connected_users = set(
            client_state['username']
            for client_state in self.connections.values()
            if client_state['channels'].intersection(user_channels))
        connected_users.discard(username)
        return connected_users

    def _get_users_in_channel(self, channel):
        """
        Returns a set of usernames which have joined the specified channel.
        """
        return set(client_state['username']
                   for client_state in self.connections.values()
                   if channel in client_state['channels'])

    def _handle_client_input(self, client_socket, input_chunk):
        """
        Parse the raw client input and determine the appropriate action.
        The chunk is appended to the input buffer, and all complete messages
        are acted on (messages terminated by CRLF). If the message matches an
        accepted format, a handler for the matched command is called.
        Otherwise a reply is returned to the client that their message was
        invalid.
        """
        client_state = self.connections[client_socket]

        input_buffer = ''.join([client_state['input_buffer'], input_chunk])
        messages = input_buffer.split(MESSAGE_END)
        client_state['input_buffer'] = messages.pop()
        self.connections[client_socket] = client_state

        for message in messages:
            logging.debug('From client: {!r}'.format(message))

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

        active_usernames = self.users.keys()
        while True:
            self.user_index += 1
            username = 'user{}'.format(self.user_index)
            if username not in active_usernames:
                break

        self.users[username] = connection
        self.connections[connection] = {
            'channels': set(),
            'input_buffer': '',
            'username': username
        }
        self._send_reply(connection, NICK_CHANGE_ACCEPTED, username)

        connection_state = str(connection.getpeername())
        logging.debug("{user} {state} connected".format(
            user=username,
            state=connection_state))

    def _process_invalid_message(self, client_socket, message):
        """
        Server does not recognize the format of the client message.
        Respond with an error.
        """
        logging.debug('Unrecognized client message: {!r}'.format(message))
        return self._send_error(client_socket, UNRECOGNIZED_CLIENT_MESSAGE)

    def _process_join_command(self, client_socket, channel):
        """
        Handle a JOIN command from a client.
        Error responses:
          - Invalid channel format
          - Channel already joined
        """
        if not CHANNEL_RE.match(channel):
            return self._send_error(client_socket, INVALID_CHANNEL_FORMAT)

        client_state = self.connections[client_socket]
        if channel in client_state['channels']:
            return self._send_error(client_socket, CHANNEL_ALREADY_JOINED)

        joining_user = client_state['username']
        for other_user in self._get_users_in_channel(channel):
            receiving_socket = self.users[other_user]
            self._send_message(receiving_socket, CLIENT_JOINED_CHANNEL,
                               joining_user, channel)

        client_state['channels'].add(channel)
        self.connections[client_socket] = client_state
        return self._send_reply(client_socket, CHANNEL_JOINED, channel)

    def _process_leave_command(self, client_socket, channel):
        """
        Handle a LEAVE command from a client.
        Error responses:
          - Invalid channel format
          - Channel not currently joined
        """
        if not CHANNEL_RE.match(channel):
            return self._send_error(client_socket, INVALID_CHANNEL_FORMAT)

        client_state = self.connections[client_socket]
        if channel not in client_state['channels']:
            return self._send_error(client_socket, CHANNEL_NOT_JOINED)

        leaving_username = client_state['username']
        client_state['channels'].discard(channel)
        self.connections[client_socket] = client_state

        self._send_user_left_channel_message(leaving_username, channel)
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
        if not channel:
            return self._send_reply(client_socket, CHANNEL_LIST,
                                    *self._active_channels)

        if not CHANNEL_RE.match(channel):
            return self._send_error(client_socket, INVALID_CHANNEL_FORMAT)

        if channel not in self._active_channels:
            return self._send_error(client_socket, NONEXISTENT_CHANNEL)

        users_in_channel = self._get_users_in_channel(channel)
        return self._send_reply(client_socket, CHANNEL_USERS,
                                channel, *users_in_channel)

    def _process_nick_command(self, client_socket, nick):
        """
        Handle a NICK command from a client requesting to change username.
        Error responses sent for:
          - Invalid nick format
          - Current nick already matches requested nick
          - A different user has already been given the requested nick
        """
        if not NICK_RE.match(nick):
            return self._send_error(client_socket, INVALID_NICK_FORMAT)

        client_state = self.connections[client_socket]
        current_nick = client_state['username']
        if nick == current_nick:
            return self._send_error(client_socket, USERNAME_ALREADY_CURRENT)

        if nick in self.users:
            return self._send_error(client_socket, USERNAME_UNAVAILABLE)

        self.users[nick] = client_socket
        del self.users[current_nick]
        client_state['username'] = nick
        self.connections[client_socket] = client_state

        for connected_user in self._get_connected_users(nick):
            connected_socket = self.users[connected_user]
            self._send_message(connected_socket, NICK_CHANGED,
                               current_nick, nick)

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
        message_match = PRIVATE_MESSAGE_RE.match(message_args)
        if not message_match:
            return self._send_error(client_socket, UNRECOGNIZED_CLIENT_MESSAGE)

        match_dict = message_match.groupdict()
        recipient_username = match_dict['username']
        message = match_dict['message']
        if recipient_username not in self.users:
            return self._send_error(client_socket, NONEXISTENT_USER)

        sending_username = self.connections[client_socket]['username']
        recipient_socket = self.users[recipient_username]
        # TODO: Send message back to sender
        self._send_message(recipient_socket, PRIVATE_MESSAGE,
                           sending_username, message)
        self._send_reply(client_socket, PRIVATE_MSG_DELIVERED)

    def _process_public_message(self, client_socket, message_args):
        """
        Handle a MSG command from a client sending a public message to a
        channel.
        Error responses sent for:
          - Unrecognized public message args, the receiving channel must be
            present
          - Specified channel doesnt exist
          - User is has not joined the channel to which message was sent
        """
        message_match = PUBLIC_MESSAGE_RE.match(message_args)
        if not message_match:
            return self._send_error(client_socket, UNRECOGNIZED_CLIENT_MESSAGE)

        match_dict = message_match.groupdict()
        channel = match_dict['channel']
        message = match_dict['message']
        if channel not in self._active_channels:
            return self._send_error(client_socket, NONEXISTENT_CHANNEL)

        client_state = self.connections[client_socket]
        if channel not in client_state['channels']:
            return self._send_error(client_socket, USER_NOT_IN_CHANNEL)

        sending_username = client_state['username']
        recipient_usernames = self._get_users_in_channel(channel)
        for recipient_username in recipient_usernames:
            receiving_socket = self.users[recipient_username]
            self._send_message(receiving_socket, PUBLIC_MESSAGE,
                               sending_username, channel, message)

    def _process_quit_command(self, client_socket, _):
        """
        QUIT command detected by client, no further processing needed
        """
        self._close_client_connection(client_socket)

    def _send_error(self, client_socket, error_code):
        return self._send_to_client(client_socket, ERROR, error_code)

    def _send_message(self, client_socket, msg_code, *args):
        return self._send_to_client(client_socket, MESSAGE, msg_code, *args)

    def _send_reply(self, client_socket, reply_code, *args):
        return self._send_to_client(client_socket, REPLY, reply_code, *args)

    def _send_to_client(self, client_socket, message_type, code, *args):
        """
        Construct the message and return the response to the client.
        """
        space = ' ' if args else ''
        response = '{message_type} {code}{space}{args}{end}'.format(
            message_type=message_type,
            code=code,
            space=space,
            args=' '.join(args),
            end=MESSAGE_END)

        logging.debug('Response: {!r}'.format(response))
        return client_socket.send(response)

    def _send_user_left_channel_message(self, username, channel):
        """
        Send a message to all remaining clients in the channel that the
        specified user has left.
        """
        for other_user in self._get_users_in_channel(channel):
            receiving_socket = self.users[other_user]
            self._send_message(receiving_socket, CLIENT_LEFT_CHANNEL,
                               username, channel)

    def _show_server_state(self):
        """
        Hit Enter while the server is running in debug mode to dump server
        state to the console.
        """
        logging.debug('Connections:')
        for connection, client_state in self.connections.iteritems():
            logging.debug('\tSocket: {}'.format(connection))
            logging.debug('\tChannels: {}'.format(client_state['channels']))
            logging.debug('\tInput Buffer: {}'
                          .format(client_state['input_buffer']))
            logging.debug('\tUsername: {}\n'.format(client_state['username']))

        logging.debug('Users:')
        for username, connection in self.users.iteritems():
            logging.debug('\tSocket: {}'.format(connection))
            logging.debug('\tUsername: {}\n'.format(username))
        return

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
                    [self.server_socket, sys.stdin] +
                    self.connections.keys())
                input_sockets, _, _ = select.select(all_connections, [], [])
                for ready_socket in input_sockets:
                    if ready_socket == self.server_socket:
                        self._initialize_client_connection()
                    elif ready_socket == sys.stdin:
                        sys.stdin.readline()
                        self._show_server_state()
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
            for client_socket in self.connections.keys():
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
