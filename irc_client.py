#!/usr/bin/env python
"""
Chris Schmitz
CS 494
"""
import argparse
import re
import select
import socket
import sys

from termcolor import colored

BUF_SIZE = 4096
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 12000
MESSAGE_END = '\r\n'
SOCKET_TIMEOUT = 3

CHANNEL_RE = re.compile(r'^#[_a-zA-Z]\w{0,30}$')
NICK_RE = re.compile(r'^[_a-zA-Z]\w{0,31}$')

PRIVATE_MESSAGE_RE = re.compile(r'^(?P<username>[_a-zA-Z]\w{0,31}) ')
PUBLIC_MESSAGE_RE = re.compile(r'^(?P<username>[_a-zA-Z]\w{0,31})'
                               ' (?P<channel>#[_a-zA-Z]\w{0,30}) ')
SERVER_RESPONSE_RE = re.compile(r'^(?P<message_type>MSG|RPL|ERROR)'
                                ' (?P<code>\d{3})(?: |$)')
USER_COMMAND_RE = re.compile(r'^\s*/(?P<command>[a-z]+)(?: |$)')


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
        self.socket_buffer = ''
        self.username = None

        self.error_text = {
            400: 'Invalid command',
            401: 'Invalid nick format',
            402: 'Username already set',
            403: 'Username is not available',
            404: 'Invalid channel format',
            405: 'Channel already joined',
            406: 'Cannot leave channel that is not joined',
            407: 'Channel does not exist',
            408: 'User does not exist',
            409: 'Must join channel before sending messages'
        }
        self.server_response_handlers = {
            'ERROR': self._error_handler,
            'MSG': self._message_handler,
            'RPL': self._reply_handler
        }

    def _display_intro(self):
        print '\n  Chris Schmitz CS494 IRC Client'
        print '  Type "/help" for list of commands\n'

    def _display_message(self, message):
        sys.stdout.write('\n  *** {}\n'.format(message))
        sys.stdout.flush()

    def _display_response(self, message, br=False, color='yellow'):
        br = '\n' if br else ''
        formatted_msg = '{br}  *** {msg}\n'.format(msg=message, br=br)
        sys.stdout.write(colored(formatted_msg, color))
        sys.stdout.flush()

    def _error_handler(self, error_code, _):
        error = 'ERROR: {}'.format(self.error_text[error_code])
        self._display_response(error, color='red')

    def _handle_channel_join(self, joined_channel):
        self.channels.add(joined_channel)
        if not self.current_channel:
            self.current_channel = joined_channel
        self._display_response('Joined {}'.format(joined_channel))

    def _handle_channel_left(self, left_channel):
        self.channels.discard(left_channel)
        if not self.channels:
            self.current_channel = None
        elif self.current_channel == left_channel:
            self.current_channel = next(iter(self.channels))
        self._display_response('Left {}'.format(left_channel))

    def _handle_channel_list(self, channel_list):
        if not channel_list:
            return self._display_response('No active channels')
        self._display_response('Active channels:')
        for channel in sorted(channel_list.split(' ')):
            print '\t{}'.format(channel)

    def _handle_channel_users(self, channel_list_response):
        channel_user_list = channel_list_response.split(' ')
        channel = channel_user_list.pop(0)
        self._display_response('Users in channel {}:'.format(channel))
        for username in sorted(channel_user_list):
            message = '\t{}'.format(username)
            if username == self.username:
                message = '\t* {}'.format(username)
            print message

    def _handle_client_joined_channel(self, join_info):
        user, channel = join_info.split(' ')
        message = '{user} joined {channel}'.format(user=user, channel=channel)
        self._display_response(message, br=True)

    def _handle_client_left_channel(self, leave_info):
        user, channel = leave_info.split(' ')
        message = '{user} left {channel}'.format(user=user, channel=channel)
        self._display_response(message, br=True)

    def _handle_nick_change(self, username):
        self.username = username
        self._display_response('Current username: {}'.format(username))

    def _handle_other_user_nick_change(self, nick_update):
        old_nick, new_nick = nick_update.split(' ')
        message = '{old_nick} changed nick to {new_nick}'.format(
            old_nick=old_nick,
            new_nick=new_nick)
        self._display_response(message, br=True)

    def _handle_private_message(self, message_text):
        return

    def _handle_public_message(self, message_text):
        message_match = PUBLIC_MESSAGE_RE.match(message_text)
        if message_match:
            match_text = message_match.group()
            match_dict = message_match.groupdict()
            username = match_dict['username']
            channel = match_dict['channel']
            linebreak = '\n'
            color = 'green'
            if username == self.username:
                linebreak = ''
                color = 'cyan'

            message = ('{br}  >>> {channel} {user} {msg}\n'.format(
                br=linebreak,
                channel=channel,
                user=username,
                msg=message_text[len(match_text):]))
            sys.stdout.write(colored(message, color))
            sys.stdout.flush()

    def _handle_server_input(self, input_chunk):
        socket_input = ''.join([self.socket_buffer, input_chunk])
        messages = socket_input.split(MESSAGE_END)
        self.socket_buffer = messages.pop()
        for message in messages:
            response_match = SERVER_RESPONSE_RE.match(message)
            if response_match:
                match_text = response_match.group()
                match_dict = response_match.groupdict()
                message_type = match_dict['message_type']
                response_code = int(match_dict['code'])
                response_text = message[len(match_text):]
                handler = self.server_response_handlers[message_type]
                handler(response_code, response_text)
                continue
            print 'Unrecognized server response: {}'.format(message)
        return

    def _message_handler(self, message_code, message_text):
        handlers = {
            200: self._handle_public_message,
            201: self._handle_private_message,
            202: self._handle_client_joined_channel,
            203: self._handle_client_left_channel,
            204: self._handle_other_user_nick_change
        }
        return handlers[message_code](message_text)

    def _reply_handler(self, reply_code, reply_text):
        handlers = {
            301: self._handle_nick_change,
            302: self._handle_channel_join,
            303: self._handle_channel_left,
            304: self._handle_channel_list,
            305: self._handle_channel_users
        }
        return handlers[reply_code](reply_text)

    def _show_prompt(self):
        channel = self.current_channel or '*none*'
        sys.stdout.write('{username} {channel} $ '.format(
            username=self.username,
            channel=channel))
        sys.stdout.flush()

    def _translate_user_input(self, input_chunk):
        message = ''.join([input_chunk, MESSAGE_END])
        return message

    def connect(self):
        self._display_intro()

        active = True
        try:
            while active:
                ready_sources, _, _ = select.select(
                    [self.client_socket, sys.stdin], [], [])
                for ready_source in ready_sources:
                    if ready_source == self.client_socket:
                        input_chunk = self.client_socket.recv(BUF_SIZE)
                        if not input_chunk:
                            active = False
                            break
                        self._handle_server_input(input_chunk)
                        self._show_prompt()
                    elif ready_source == sys.stdin:
                        input_chunk = sys.stdin.readline().strip()
                        if input_chunk:
                            message = self._translate_user_input(input_chunk)
                            self.client_socket.send(message)
                        # self._show_prompt()
        finally:
            print 'Connection terminated, exiting client'
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
