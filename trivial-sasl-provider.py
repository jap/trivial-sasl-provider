#!/usr/bin/env python3

"""Trivial sasl provider that can be hooked up to a postfix submission server,
allowing all users to log in using the same password, so the botnets are scared
away but you don't have to do elaborate user management for all IOT devies that
want to submit mail.

Trivial SASL provider

(c) 2021 Jasper Spaans <j@jasper.es>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import base64
import logging
import os
import secrets
import signal
import socket
import sys
import time
from typing import Any, Dict, Optional, Tuple, Union

THE_PASSWORD = 'foobar'

socket_name = '/var/spool/postfix/private/auth'

to_wait = []

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# protocol version is 1.1 according to docs at
# https://wiki1.dovecot.org/Authentication%20Protocol
version_major = 1
version_minor = 1

auth_mech_names = ('PLAIN',)


def handle_sigchild(signum, frame):
    pid, status, usage = os.wait3(0)
    try:
        to_wait.remove(pid)
        log.debug(f'Cleaned up child process {pid}')
    except Exception:
        log.exception(f'Error while cleaning up child process {pid}, expect zombies')


class SocketLineReader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b''

    def __call__(self) -> str:
        while 1:
            if self.buf:
                line, sep, rbuf = self.buf.partition(b'\n')
                if sep:
                    self.buf = rbuf
                    return line.decode()
            more_data = csock.recv(8192 - len(self.buf))
            if not more_data:
                return None
            self.buf += more_data


def parse_version(version: Optional[str]) -> Tuple[int, int]:
    if version is None:
        return None
    version_parts = version.split('\t')
    if len(version_parts) != 3:
        raise ValueError('Invalid version string: f{version}')
    if version_parts[0] != 'VERSION':
        raise ValueError('Invalid version string: f{version}')
    major = int(version_parts[1])
    minor = int(version_parts[2])
    return (major, minor)


def parse_cpid(cpid: Optional[str]) -> Optional[int]:
    if cpid is None:
        return None
    cpid_parts = cpid.split('\t')
    if len(cpid_parts) != 2:
        raise ValueError('Invalid cpid string: f{cpid}')
    if cpid_parts[0] != 'CPID':
        raise ValueError('Invalid cpid string: f{cpid}')
    cpid = int(cpid_parts[1])
    return cpid


def parse_auth(req: str) -> Tuple[int, str, Dict[str, Union[None, str]]]:
    pieces = req.split('\t')
    if pieces[0] != 'AUTH':
        raise ValueError('Invalid auth: {req}')
    aid = int(pieces[1])
    method = pieces[2]
    attrs = {}
    for piece in pieces[3:]:
        key, sep, val = piece.partition('=')
        if sep:
            attrs[key] = val
        else:
            attrs[key] = None
    return aid, method, attrs


def handle_socket(csock):
    log.debug(f'Handling socket {csock.fileno()}')
    csock.settimeout(900)
    readline = SocketLineReader(csock)

    # according https://wiki1.dovecot.org/Authentication%20Protocol
    # the client sends their version and pid first.
    # Dovecot doesnʼt wait, nor does Postfix, so this just parses
    # what it receives and then sends our part of the handshake back.

    version = parse_version(readline())
    if not version:
        log.info('Timed out waiting for client version')
        return
    if version[0] != version_major:
        log.error(f'Incompatible major version: {version[0]}!')
        return
    cpid = parse_cpid(readline())
    if not cpid:
        log.info('Timed out waiting for client pid')
        return
    log.info(f'Got connection from cpid {cpid} with version {version[0]}.{version[1]}')

    csock.send(f'VERSION\t{version_major}\t{version_minor}\n'.encode())
    # Contrary to the docs, Dovecot sends the MECH before SPID/CUID. If this
    # is in the wrong order, Postfix doesnʼt like it.
    for mech in auth_mech_names:
        csock.send(f'MECH\t{mech}\tplaintext\n'.encode())

    spid = os.getpid()
    csock.send(f'SPID\t{spid}\n'.encode())

    cuid = 1
    csock.send(f'CUID\t{cuid}\n'.encode())

    cookie = secrets.token_hex(16)
    csock.send(f'COOKIE\t{cookie}\n'.encode())

    csock.send(f'DONE\n'.encode())

    while 1:
        req = readline()
        if not req:
            log.debug(f'NO req')
            break
        log.debug(f'GOT REQ: {req}')
        if req.startswith('AUTH\t'):
            aid, method, args = parse_auth(req)
            try:
                if method == 'PLAIN':
                    result = handle_plain(aid, args)
                # elif method == 'LOGIN':
                #    result = handle_login(args)
                else:
                    result = f'FAIL\t{aid}\treason=unexpected method\n'
            except Exception:
                log.exception('Error while handling AUTH request')
                result = f'FAIL\t{aid}\n'
            log.debug(f'SEND RESP: {result}')
            csock.send(result.encode())
        else:
            log.info(f'Unexpected request: {req}')
            return

    return


def handle_plain(aid: int, args: Dict[str, Union[None, str]]) -> str:
    # This is where the magic happens...
    resp_b64 = args['resp']
    resp = base64.b64decode(resp_b64)
    pieces = resp.split(b'\x00')
    if len(pieces) != 3:
        raise ValueError('Incorrect authentication data')
    username = pieces[1].decode()
    password = pieces[2]

    if password == THE_PASSWORD.encode():
        return f'OK\t{aid}\tuser={username}\n'
    return f'FAIL\t{aid}\treason=wrong password\n'


def main():
    old_sigchild = signal.signal(signal.SIGCHLD, handle_sigchild)

    with socket.socket(socket.AF_UNIX) as bsock:
        try:
            os.unlink(socket_name)
            log.info(f'Removed f{socket_name}')
        except OSError:
            pass
        bsock.bind(socket_name)
        os.chmod(socket_name, 0o666)
        bsock.listen()
        log.info(f'Now listening on socket {socket_name}')
        while 1:
            csock, addr = bsock.accept()
            pid = os.fork()
            if pid == 0:
                handle_socket(csock)
                log.debug(f'Shutting down socket {csock.fileno()}')
                csock.shutdown(socket.SHUT_RDWR)
                sys.exit(0)
            else:
                log.debug(f'Child process {pid} is now handling fd {csock.fileno()}')
                csock.close()
                to_wait.append(pid)


if __name__ == '__main__':
    main()
