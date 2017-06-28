#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
import sys
import logging
import functools
import base64
import zlib
import socket as _socket
from Crypto.Util.py3compat import tobytes

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s{%(name)s}%(filename)s[line:%(lineno)d]<%(funcName)s> pid:%(process)d %(threadName)s %(levelname)s : %(message)s',
                    datefmt='%H:%M:%S', stream=sys.stdout)

logger = logging.getLogger("SRP")


def tobytes(s):
    if isinstance(s, bytes):
        return s
    elif isinstance(s, bytearray):
        return bytes(s)
    else:
        if isinstance(s, str):
            return s.encode("latin-1")
        else:
            return bytes([s])


def tostr(bs):
    return bs.decode("latin-1")


def _zlib_base_method(zlib_base_method, input_data, encoding="utf-8", errors='ignore'):
    is_string = isinstance(input_data, str)
    is_bytes = isinstance(input_data, bytes)
    if not is_string and not is_bytes:
        raise Exception("Please provide a string or a byte sequence as \
                        argument for calculation.")
    if is_string:
        input_data = input_data.encode(encoding=encoding, errors=errors)
    return zlib_base_method(input_data) & 0xffffffff


def _base64_base_method(base64_base_method, input_data, return_type=str, encoding="utf-8", errors='ignore'):
    is_string = isinstance(input_data, str)
    is_bytes = isinstance(input_data, bytes)
    if not is_string and not is_bytes:
        raise Exception("Please provide a string or a byte sequence ")
    if is_bytes:
        bytes_string = input_data
    else:
        bytes_string = input_data.encode(encoding=encoding, errors=errors)
    result = base64_base_method(bytes_string)
    if return_type is str:
        return result.decode(errors=errors)
    else:
        return result


base16_encode = functools.partial(_base64_base_method, base64.b16encode)
base16_decode = functools.partial(_base64_base_method, base64.b16decode)
base32_encode = functools.partial(_base64_base_method, base64.b32encode)
base32_decode = functools.partial(_base64_base_method, base64.b32decode)
base64_encode = functools.partial(_base64_base_method, base64.b64encode)
base64_decode = functools.partial(_base64_base_method, base64.b64decode)
if sys.version_info[0:2] >= (3, 4):
    base85_encode = functools.partial(_base64_base_method, base64.b85encode)
    base85_decode = functools.partial(_base64_base_method, base64.b85decode)
crc32 = functools.partial(_zlib_base_method, zlib.crc32)
adler32 = functools.partial(_zlib_base_method, zlib.adler32)

SPLIT_BYTES = b'\r\n \r\n'
PING_BYTES = b'0'
PONG_BYTES = b'1'
DATA_BYTES = b'2'
FINISH_WRITE_SOCKET_BYTES = b'3'

LEN_PING_BYTES = len(PING_BYTES)
LEN_PONG_BYTES = len(PONG_BYTES)
LEN_DATA_BYTES = len(DATA_BYTES)
LEN_FINISH_WRITE_SOCKET_BYTES = len(FINISH_WRITE_SOCKET_BYTES)

DATA_PRIORITY = 100
FINISH_WRITE_SOCKET_PRIORITY = 50
CONTROL_PRIORITY = 10


class SocketHelper(object):
    def __init__(self, socket: _socket.socket, parse_split_bytes=True):
        self.socket = socket  # type: _socket.socket
        self.buffer_size = 1024 * 10
        self.last_buffer = b''
        self.parse_split_bytes = parse_split_bytes

    def read(self):
        if self.parse_split_bytes:
            if self.last_buffer:
                data_arr = self.last_buffer.split(SPLIT_BYTES, 1)
                if len(data_arr) == 2:
                    self.last_buffer = data_arr[1]
                    return data_arr[0]
            while True:
                data = self.socket.recv(self.buffer_size)
                # logger.debug(data)
                if not data:
                    raise ConnectionError()
                self.last_buffer += data
                data_arr = self.last_buffer.split(SPLIT_BYTES, 1)
                if len(data_arr) == 2:
                    self.last_buffer = data_arr[1]
                    data = data_arr[0]
                    # logger.debug(data)
                    return data
        else:
            data = self.socket.recv(self.buffer_size)
            # logger.debug(data)
            if not data:
                raise ConnectionError()
            # logger.debug(data)
            return data

    def write(self, data):
        data = tobytes(data)
        if self.parse_split_bytes:
            data += SPLIT_BYTES
        # logger.debug(data)
        self.socket.send(data)
