#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from gevent import monkey

monkey.patch_all()

from functools import partial
import socket as _socket
import uuid
import json
import time
import gevent
from queue import Queue, Empty
from gevent.server import StreamServer
from .encrypt import ciphers, default_cipher_name, tostr, tobytes
from .utils import logger, SocketHelper, base85_encode, base85_decode, PING_BYTES, PONG_BYTES, DATA_BYTES, \
    FINISH_WRITE_SOCKET_BYTES, LEN_DATA_BYTES, LEN_PING_BYTES, LEN_PONG_BYTES, LEN_FINISH_WRITE_SOCKET_BYTES

listen_port_server_dict1 = {}
listen_port_server_dict2 = {}


class ListenPortServer(object):
    def __init__(self, ip, port, connect_uuid, cipher):
        self.ip = ip
        self.port = port
        self.connect_uuid = connect_uuid
        self.cipher = cipher
        self.socket_handle_socket_dict = dict()
        self.server_write_queue_dict = dict()
        self.server_write_ok_queue_dict = dict()
        self.client_queue = Queue(1)
        self.server = None  # type:StreamServer
        listen_port_server_dict1[(self.ip, self.port)] = self
        listen_port_server_dict2[self.connect_uuid] = self

    def __call__(self, *args, **kwargs):
        logger.debug("start the ListenPortServer with connect_uuid=%s" % self.connect_uuid)
        self.server = StreamServer((self.ip, self.port), self.socket_handle)
        self.server.init_socket()
        self.server.serve_forever()

    def socket_handle_read(self, socket_helper: SocketHelper, server_write_ok_queue: Queue, socket_uuid: str):
        if server_write_ok_queue.empty():
            server_write_ok_queue.put(True)
        try:
            while True:
                data_buffer = socket_helper.read()
                # logger.debug("received:%s" % data_buffer)
                # data_buffer = base85_encode(data_buffer)
                # data = {"type": "data", "socket_uuid": socket_uuid}  # , "data": data_buffer}
                # data = json.dumps(data)
                # data = self.cipher.encrypt(data)
                # data_buffer = self.cipher.encrypt(data_buffer)
                # server_write_ok_queue.get()
                # self.client_queue.put((data, data_buffer))

                data = DATA_BYTES + tobytes(socket_uuid) + data_buffer
                data = self.cipher.encrypt(data)
                server_write_ok_queue.get()
                self.client_queue.put(data, data_buffer)
        except _socket.timeout:
            pass
        except ConnectionError:
            pass
        except OSError:
            pass
        except gevent.GreenletExit:
            pass
        except gevent._socketcommon.cancel_wait_ex:
            pass

    def socket_handle_write(self, socket_helper: SocketHelper, server_write_queue: Queue, socket_uuid: str):
        try:
            while True:
                c_data = server_write_queue.get()
                if c_data is None:
                    break
                socket_helper.write(c_data)
                # json_data = {"type": "finish_write_socket", "socket_uuid": socket_uuid}
                # json_data = json.dumps(json_data)
                json_data = FINISH_WRITE_SOCKET_BYTES + tobytes(socket_uuid)
                # logger.debug("send:%s" % json_data)
                json_data = self.cipher.encrypt(json_data)
                self.client_queue.put(json_data)
        except _socket.timeout:
            pass
        except ConnectionError:
            pass
        except gevent.GreenletExit:
            pass

    def socket_handle(self, socket, address):
        logger.info("new TCP client<%s> connect" % str(address))
        socket_uuid = uuid.uuid4().hex
        server_write_queue = Queue(1)
        server_write_ok_queue = Queue(1)
        self.server_write_queue_dict[socket_uuid] = server_write_queue
        self.server_write_ok_queue_dict[socket_uuid] = server_write_ok_queue
        self.socket_handle_socket_dict[socket_uuid] = socket
        data = {"type": "new_socket", "socket_uuid": socket_uuid}
        logger.debug("send:%s" % data)
        data = json.dumps(data)
        data = self.cipher.encrypt(data)
        self.client_queue.put(data)
        socket_helper = SocketHelper(socket, parse_split_bytes=False)
        server_write_queue.get()
        r = gevent.spawn(self.socket_handle_read, socket_helper, server_write_ok_queue, socket_uuid)
        w = gevent.spawn(self.socket_handle_write, socket_helper, server_write_queue, socket_uuid)
        gevent.wait([r, w], count=1)
        gevent.killall([r, w])
        data = {"type": "close_socket", "socket_uuid": socket_uuid}
        logger.debug("send:%s" % data)
        data = json.dumps(data)
        data = self.cipher.encrypt(data)
        self.server_write_queue_dict.pop(socket_uuid, None)
        self.server_write_ok_queue_dict.pop(socket_uuid, None)
        self.socket_handle_socket_dict.pop(socket_uuid, None)
        self.client_queue.put(data)

    def parse_client_read(self, reverse_proxy_server):
        try:
            while True:
                try:
                    data_buffer = reverse_proxy_server.socket_helper.read()
                    c_data = self.cipher.decrypt(data_buffer)
                    # logger.debug("received:%s" % c_data)
                    if c_data == PING_BYTES:
                        logger.debug("received ping")
                        data = PONG_BYTES
                        data = self.cipher.encrypt(data)
                        self.client_queue.put(data)
                        continue
                    if c_data == PONG_BYTES:
                        logger.debug("received pong")
                        continue
                    if c_data.startswith(DATA_BYTES):
                        c_data = c_data[LEN_DATA_BYTES:]
                        socket_uuid = tostr(c_data[:32])
                        # logger.debug(socket_uuid)
                        socket_data = c_data[32:]
                        server_write_queue = self.server_write_queue_dict[socket_uuid]
                        server_write_queue.put(socket_data)
                        continue
                    if c_data.startswith(FINISH_WRITE_SOCKET_BYTES):
                        # logger.debug("received:%s" % c_data)
                        c_data = c_data[LEN_FINISH_WRITE_SOCKET_BYTES:]
                        socket_uuid = tostr(c_data)
                        # logger.debug(socket_uuid)
                        server_write_ok_queue = self.server_write_ok_queue_dict[socket_uuid]
                        server_write_ok_queue.put(True)
                        continue
                    if c_data.startswith(b'{'):
                        c_json = json.loads(c_data)
                        data_type = c_json["type"]
                        if data_type == "data":
                            socket_uuid = c_json["socket_uuid"]
                            socket_data = reverse_proxy_server.socket_helper.read()  # c_json["data"]
                            socket_data = self.cipher.decrypt(socket_data)
                            server_write_queue = self.server_write_queue_dict[socket_uuid]
                            # socket_data = base85_decode(socket_data, return_type=bytes)
                            # logger.debug(socket_data)
                            server_write_queue.put(socket_data)
                        elif data_type == "finish_write_socket":
                            # logger.debug("received:%s" % c_data)
                            socket_uuid = c_json["socket_uuid"]
                            server_write_ok_queue = self.server_write_ok_queue_dict[socket_uuid]
                            server_write_ok_queue.put(True)
                        elif data_type == "finish_new_socket":
                            # logger.debug("received:%s" % c_data)
                            socket_uuid = c_json["socket_uuid"]
                            server_write_queue = self.server_write_queue_dict[socket_uuid]
                            server_write_queue.put(True)
                        elif data_type == "close_socket":
                            logger.debug("received:%s" % c_data)
                            socket_uuid = c_json["socket_uuid"]
                            self.socket_handle_socket_dict[socket_uuid].close()
                            # server_write_queue = self.server_write_queue_dict[socket_uuid]
                            # server_write_queue.put(None)
                except ValueError:
                    pass
                except KeyError:
                    pass
        except _socket.timeout:
            logger.debug("exit")
        except ConnectionError:
            logger.debug("exit")
        except gevent.GreenletExit:
            logger.debug("exit")

    def parse_client_write(self, reverse_proxy_server):
        try:
            while True:
                try:
                    s_data = self.client_queue.get(timeout=reverse_proxy_server.socket_timeout / 2)
                    if s_data is None:
                        break
                except Empty:
                    s_data = PING_BYTES
                    logger.debug("send ping")
                    s_data = self.cipher.encrypt(s_data)
                if isinstance(s_data, (list, tuple)):
                    for item in s_data:
                        # item = self.cipher.encrypt(item)
                        reverse_proxy_server.socket_helper.write(item)
                else:
                    # s_data = self.cipher.encrypt(s_data)
                    reverse_proxy_server.socket_helper.write(s_data)
        except _socket.timeout:
            pass
        except ConnectionError:
            pass
        except gevent.GreenletExit:
            pass
        logger.debug("exit")

    def parse_client(self, reverse_proxy_server):
        r = gevent.spawn(self.parse_client_read, reverse_proxy_server)
        w = gevent.spawn(self.parse_client_write, reverse_proxy_server)
        gevent.wait([r, w], count=1)
        gevent.killall([r, w])

    def close(self):
        logger.debug("close the ListenPortServer with connect_uuid=%s" % self.connect_uuid)
        listen_port_server_dict1.pop((self.ip, self.port), None)
        listen_port_server_dict2.pop(self.connect_uuid, None)
        if self.server:
            self.server.stop()
            self.client_queue.put(None)
            for item in self.server_write_queue_dict.values():
                item.put(None)


class ReverseProxyServer(object):
    def __init__(self, method, password, socket, address):
        self.method = method
        self.password = password
        self.socket = socket  # type: _socket.socket
        self.address = address
        self.cipher = ciphers[method](password)
        self.socket_helper = SocketHelper(self.socket)
        self.buffer_size = 1024
        self.socket_timeout = 30

    def __call__(self, *args, **kwargs):
        logger.info("new SRP client<%s> connect" % str(self.address))
        self.socket.settimeout(self.socket_timeout)
        data_buffer = self.socket_helper.read()
        if not data_buffer:
            logger.debug("close the socket")
            self.socket.close()
            return
        first_data = self.cipher.decrypt(data_buffer)
        if first_data != b'ok':
            logger.debug("close the socket")
            self.socket.close()
            return
        self.socket_helper.write(self.cipher.encrypt(b"ok"))
        listen_port_server_list = list()
        try:
            while True:
                data_buffer = self.socket_helper.read()
                config_data = self.cipher.decrypt(data_buffer)
                # logger.debug("received:%s" % config_data)
                if config_data == PING_BYTES:
                    self.socket_helper.write(self.cipher.encrypt(PONG_BYTES))
                    continue
                if config_data == PONG_BYTES:
                    continue
                config_json = json.loads(config_data)
                data_type = config_json["type"]
                if data_type == "control_listen":
                    logger.debug("received:%s" % config_data)
                    listen_ip = config_json["listen_ip"]
                    listen_port = config_json["listen_port"]
                    listen_port_server = listen_port_server_dict1.get((listen_ip, listen_port), None)
                    if not listen_port_server:
                        connect_uuid = uuid.uuid4().hex
                        listen_port_server = ListenPortServer(listen_ip, listen_port, connect_uuid, self.cipher)
                        gevent.spawn(listen_port_server)
                        json_data = {"data_type": "accept", "connect_uuid": connect_uuid}
                        json_data = json.dumps(json_data)
                        logger.debug("send:%s" % json_data)
                        json_data = self.cipher.encrypt(json_data)
                        self.socket_helper.write(json_data)
                        listen_port_server_list.append(listen_port_server)
                    else:
                        json_data = {"data_type": "refuse"}
                        json_data = json.dumps(json_data)
                        logger.debug("send:%s" % json_data)
                        json_data = self.cipher.encrypt(json_data)
                        self.socket_helper.write(json_data)

                elif data_type == "from_uuid":
                    logger.debug("received:%s" % config_data)
                    connect_uuid = config_json["connect_uuid"]
                    listen_port_server = listen_port_server_dict2.get(connect_uuid, None)
                    if not listen_port_server:
                        json_data = {"data_type": "refuse"}
                        json_data = json.dumps(json_data)
                        logger.debug("send:%s" % json_data)
                        json_data = self.cipher.encrypt(json_data)
                        self.socket_helper.write(json_data)
                        logger.debug("close the socket")
                        self.socket.close()
                        return
                    else:
                        json_data = {"data_type": "accept"}
                        json_data = json.dumps(json_data)
                        logger.debug("send:%s" % json_data)
                        json_data = self.cipher.encrypt(json_data)
                        self.socket_helper.write(json_data)
                        listen_port_server.parse_client(self)
                        logger.debug("close the socket")
                        self.socket.close()
                        return
        except _socket.timeout:
            pass
        except ConnectionError:
            pass
        except ValueError:
            pass
        except KeyError:
            pass
        finally:
            for listen_port_server in listen_port_server_list:
                listen_port_server.close()
            logger.debug("close the socket")
            self.socket.close()
            return


def socket_handle(password, method, socket, address):
    server = ReverseProxyServer(password, method, socket, address)
    server()


def server_main(ip="0.0.0.0", port=10086, password="password", method=default_cipher_name):
    logger.info("start server on %s:%d" % (ip, port))
    server = StreamServer((ip, port), partial(socket_handle, method, password))
    server.init_socket()
    server.serve_forever()
