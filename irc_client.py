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

try:
    from termcolor import colored
except ImportError:
    termcolor_url = 'https://pypi.python.org/pypi/termcolor'
    print ('>>> termcolor import failed.\n>>> Download from {url} '
           'for colored output'.format(url=termcolor_url))
    def colored(msg, _):
        return msg

BUF_SIZE = 4096
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 12000
MESSAGE_END = '\r\n'
SOCKET_TIMEOUT = 3

CLEAR_LINE = '\x1b[2K\r'
CURSOR_UP = '\033[1A'

CHANNEL_RE = re.compile(r'^#[_a-zA-Z]\w{0,30}$')
NICK_RE = re.compile(r'^[_a-zA-Z]\w{0,31}$')

PRIVATE_MESSAGE_RE = re.compile(r'^(?P<username>[_a-zA-Z]\w{0,31}) ')
PUBLIC_MESSAGE_RE = re.compile(r'^(?P<username>[_a-zA-Z]\w{0,31})'
                               ' (?P<channel>#[_a-zA-Z]\w{0,30}) ')
SERVER_RESPONSE_RE = re.compile(r'^(?P<message_type>MSG|RPL|ERROR)'
                                ' (?P<code>\d{3})(?: |$)')
USER_COMMAND_RE = re.compile(r'^\s*(?P<command>/[a-zA-Z]+)(?: |$)')

ERROR_TEXT = {
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

SERVER_COMMAND_MAPPING = {
    '/join': 'JOIN',
    '/leave': 'LEAVE',
    '/list': 'LIST',
    '/msg': 'PRVMSG',
    '/nick': 'NICK',
    '/quit': 'QUIT'
}


class IRCClient(object):
    """
    Encapsulates a client connection to an IRC server.
    An instance of this class is instantiated with a hostname and port number,
    and represents a single client connection.
    """
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

        self.server_response_handlers = {
            'ERROR': self._server_error_handler,
            'MSG': self._message_handler,
            'RPL': self._reply_handler
        }

    def _clear_lines(self, num_lines=1):
        """
        Clear a specified number of lines recently written to stdout.
        """
        if not num_lines:
            return

        sys.stdout.write(CLEAR_LINE)
        for _ in range(num_lines - 1):
            sys.stdout.write(CURSOR_UP)
            sys.stdout.write(CLEAR_LINE)
        sys.stdout.flush()

    def _client_error_handler(self, error):
        self._display_response(error, color='red')

    def _display_help(self):
        color = 'green'
        print colored('\n\t/join #channel', color)
        print colored('\t/leave #channel', color)
        print colored('\t/list [#channel]', color)
        print colored('\t/msg nick message', color)
        print colored('\t/nick newnick', color)
        print colored('\t/quit', color)
        print colored('\t/switch #channel\n', color)

    def _display_intro(self):
        print '\n  Chris Schmitz CS494 IRC Client'
        print '  Type "/help" for list of commands\n'

    def _display_response(self, message, br=False, color='yellow'):
        """
        Server responses to client commands are specially formatted.
        """
        br = '\n' if br else ''
        formatted_msg = '{br}  *** {msg}\n'.format(msg=message, br=br)
        sys.stdout.write(colored(formatted_msg, color))
        sys.stdout.flush()

    def _handle_channel_join(self, joined_channel):
        """
        Add the newly joined channel to the set of currently joined channels,
        and make it the current channel.
        """
        self.channels.add(joined_channel)
        self.current_channel = joined_channel
        self._display_response('Joined {}'.format(joined_channel))

    def _handle_channel_left(self, left_channel):
        """
        Remove the channel that was left from the set of joined channels.
        If there are still joined channels remaining, randomly pick one to
        make current.  Otherwise reset current channel to None.
        """
        self.channels.discard(left_channel)
        if not self.channels:
            self.current_channel = None
        elif self.current_channel == left_channel:
            self.current_channel = next(iter(self.channels))
        self._display_response('Left {}'.format(left_channel))

    def _handle_channel_list(self, channel_list):
        """
        List all currently active channels.
        A '*' indicates the client has joined that channel.
        """
        if not channel_list:
            return self._display_response('No active channels')

        self._display_response('Active channels:')
        for channel in sorted(channel_list.split(' ')):
            spacing = '* ' if channel in self.channels else ''
            message = ''.join(['\t', spacing, channel])
            print colored(message, 'yellow')

    def _handle_channel_users(self, channel_list_response):
        """
        List the users in a specified channel.
        '*' indicates this clients username.
        """
        channel_user_list = channel_list_response.split(' ')
        channel = channel_user_list.pop(0)
        self._display_response('Users in channel {}:'.format(channel))
        for username in sorted(channel_user_list):
            spacing = '* ' if username == self.username else ''
            message = ''.join(['\t', spacing, username])
            print colored(message, 'yellow')

    def _handle_client_command(self, command, command_args):
        """
        Handler for client side only commands that are not sent to the server.
        The switch command changes the current channel, which specifies where
        messages are sent (since clients can join multiple channels).
        The help command displays the list of available commands.
        """
        if command == '/switch':
            channel = command_args
            if not channel:
                self._client_error_handler('Must specify a channel to chat')
            elif channel not in self.channels:
                self._client_error_handler('Channel must be joined before '
                                           'chatting (use /join command)')
            else:
                self.current_channel = channel
        elif command == '/help':
            self._display_help()
        else:
            self._client_error_handler('Unknown command: {!r}'.format(command))

    def _handle_client_joined_channel(self, join_info):
        """
        Show message for another client joining a channel.
        """
        user, channel = join_info.split(' ')
        message = '{user} joined {channel}'.format(user=user, channel=channel)
        self._display_response(message, br=True)

    def _handle_client_left_channel(self, leave_info):
        """
        Show message for another client leaving a channel.
        """
        user, channel = leave_info.split(' ')
        message = '{user} left {channel}'.format(user=user, channel=channel)
        self._display_response(message, br=True)

    def _handle_nick_change(self, username):
        """
        Update current/nick username
        """
        self.username = username
        self._display_response('Current username: {}'.format(username))

    def _handle_other_user_nick_change(self, nick_update):
        """
        Inform client that another client changed their nick
        """
        old_nick, new_nick = nick_update.split(' ')
        message = '{old_nick} changed nick to {new_nick}'.format(
            old_nick=old_nick,
            new_nick=new_nick)
        self._display_response(message, br=True)

    def _handle_private_message(self, message_text):
        """
        A private message was received.
        Determine who sent it, then print it to stdout.
        """
        message_match = PRIVATE_MESSAGE_RE.match(message_text)
        if not message_match:
            return

        match_text = message_match.group()
        match_dict = message_match.groupdict()
        username = match_dict['username']
        linebreak = '\n'
        color = 'green'
        if username == self.username:
            linebreak = ''
            color = 'cyan'

        message = ('{br}  >>> *{user}*: {msg}\n'.format(
            br=linebreak,
            user=username,
            msg=message_text[len(match_text):]))
        sys.stdout.write(colored(message, color))
        sys.stdout.flush()

    def _handle_private_msg_delivered(self, _):
        """
        Acknowledge receipt of private message delivery.
        """
        pass

    def _handle_public_message(self, message_text):
        """
        A public message was received.
        Determine who sent it, and from which channel, then print it to stdout.
        """
        message_match = PUBLIC_MESSAGE_RE.match(message_text)
        if not message_match:
            return

        match_text = message_match.group()
        match_dict = message_match.groupdict()
        username = match_dict['username']
        channel = match_dict['channel']
        linebreak = '\n'
        color = 'green'
        if username == self.username:
            linebreak = ''
            color = 'cyan'

        message = ('{br}  >>> {channel} {user}: {msg}\n'.format(
            br=linebreak,
            channel=channel,
            user=username,
            msg=message_text[len(match_text):]))
        sys.stdout.write(colored(message, color))
        sys.stdout.flush()

    def _handle_server_input(self, input_chunk):
        """
        Input chunks from the server are combined with the input buffer
        and split based on message delimiter. Server responses are recognized
        using a regex to detect the message type and status code, and the
        appropriate handler is invoked.
        """
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

    def _handle_user_input(self, input_chunk):
        """
        User input is translated into commands the server can interpret.
        By default these are just standard messages. However at least
        one channel must be joined to chat.
        """
        server_command = 'MSG'
        channel = self.current_channel
        command_args = '{channel} {msg}'.format(channel=channel,
                                                msg=input_chunk)

        command_match = USER_COMMAND_RE.match(input_chunk)
        if command_match:
            match_text = command_match.group()
            match_dict = command_match.groupdict()
            command = match_dict['command'].lower()
            command_args = input_chunk[len(match_text):]
            if command not in SERVER_COMMAND_MAPPING:
                self._handle_client_command(command, command_args)
                return
            server_command = SERVER_COMMAND_MAPPING[command]

        if server_command == 'MSG' and not channel:
            self._client_error_handler('Must join a channel to chat')
            return

        message = '{command} {args}{end}'.format(command=server_command,
                                                 args=command_args,
                                                 end=MESSAGE_END)
        return self.client_socket.send(message)

    def _message_handler(self, message_code, message_text):
        """
        Handle each type of MSG response from the server
        """
        handlers = {
            200: self._handle_public_message,
            201: self._handle_private_message,
            202: self._handle_client_joined_channel,
            203: self._handle_client_left_channel,
            204: self._handle_other_user_nick_change
        }
        return handlers[message_code](message_text)

    def _reply_handler(self, reply_code, reply_text):
        """
        Handle each type of RPL response from the server
        """
        handlers = {
            301: self._handle_nick_change,
            302: self._handle_channel_join,
            303: self._handle_channel_left,
            304: self._handle_channel_list,
            305: self._handle_channel_users,
            306: self._handle_private_msg_delivered
        }
        return handlers[reply_code](reply_text)

    def _server_error_handler(self, error_code, _):
        """
        Servers errors are displayed to console in red text.
        """
        error = 'ERROR: {}'.format(ERROR_TEXT[error_code])
        self._display_response(error, color='red')

    def _show_prompt(self):
        """
        The user prompt reflects the client nick and current channel
        """
        channel = self.current_channel or '*none*'
        sys.stdout.write('{username} {channel} $ '.format(
            username=self.username,
            channel=channel))
        sys.stdout.flush()

    def connect(self):
        """
        Loop infinitely, listening for server socket data and user input from
        stdin. The program exits when an empty input chunk is received
        (server disconnected), or the client quits through CTRL-C/QUIT command.
        """
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
                            message_sent = self._handle_user_input(input_chunk)
                            if not message_sent:
                                self._show_prompt()
                        else:
                            self._clear_lines(2)
                            self._show_prompt()
        except KeyboardInterrupt:
            pass
        finally:
            print '\nConnection terminated, exiting client'
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
