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
import gevent
from argparse import ArgumentParser
from queue import PriorityQueue, Queue, Empty
from .encrypt import ciphers, default_cipher_name
from .utils import logger, SocketHelper, base85_encode, base85_decode, SPLIT_BYTES, PING_BYTES, PONG_BYTES, DATA_BYTES, \
    FINISH_WRITE_SOCKET_BYTES, LEN_DATA_BYTES, LEN_PING_BYTES, LEN_PONG_BYTES, LEN_FINISH_WRITE_SOCKET_BYTES, \
    DATA_PRIORITY, FINISH_WRITE_SOCKET_PRIORITY, CONTROL_PRIORITY


class ReverseProxyClient(object):
    def __init__(self, ip, port, password, method, upstream_ip, upstream_port, listen_ip, listen_port):
        self.ip = ip
        self.port = port
        self.password = password
        self.method = method
        self.upstream_ip = upstream_ip
        self.upstream_port = upstream_port
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.cipher = ciphers[method](password)
        self.cipher2 = self.cipher.clone()
        self.server_socket = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self.server_socket_helper = SocketHelper(self.server_socket)
        self.thread_list = list()
        self.server_socket2_write_queue = PriorityQueue()
        self.upstream_write_queue_dict = dict()
        self.upstream_write_ok_queue_dict = dict()
        self.upstream_socket_dict = dict()
        self.socket_timeout = 30

    def do_ping_pong(self):
        try:
            while True:
                data = PING_BYTES
                logger.debug("send ping")
                self.server_socket_helper.write(self.cipher.encrypt(data))
                data = self.server_socket_helper.read()
                data = self.cipher.decrypt(data)
                if data != PONG_BYTES:
                    logger.debug("received:%s" % data)
                    break
                logger.debug("received pong")
                gevent.sleep(self.socket_timeout / 2)
        except _socket.timeout:
            logger.debug("timeout")
            pass
        except ConnectionError:
            logger.debug("socket closed")
            pass
        except OSError as e:
            logger.debug(e.strerror)
            pass
        except gevent.GreenletExit:
            logger.debug("green let exit")
            pass
        except gevent._socketcommon.cancel_wait_ex:
            logger.debug("socket closed")
            pass
        logger.debug("exit")

    def __call__(self, *args, **kwargs):
        self.server_socket.settimeout(self.socket_timeout)
        self.server_socket.connect((self.ip, self.port))
        self.server_socket_helper.write(self.cipher.encrypt(b"ok"))
        data_buffer = self.server_socket_helper.read()
        if not data_buffer:
            logger.debug("close the socket")
            self.server_socket.close()
            return
        first_data = self.cipher.decrypt(data_buffer)
        logger.debug("received:%s" % first_data)
        if first_data != b'ok':
            logger.debug("close the socket")
            self.server_socket.close()
            return
        json_data = {"type": "control_listen", "listen_ip": self.listen_ip, "listen_port": self.listen_port}
        json_data = json.dumps(json_data)
        logger.debug("send:%s" % json_data)
        json_data = self.cipher.encrypt(json_data)
        self.server_socket_helper.write(json_data)
        data_buffer = self.server_socket_helper.read()
        json_data = self.cipher.decrypt(data_buffer)
        logger.debug("received:%s" % json_data)
        json_data = json.loads(json_data)
        if json_data["data_type"] != "accept":
            logger.debug("close the socket")
            self.server_socket.close()
            return
        connect_uuid = json_data["connect_uuid"]
        do_ping_pong = gevent.spawn(self.do_ping_pong)
        self.thread_list.append(do_ping_pong)
        while not do_ping_pong.ready():
            try:
                self.parse_server_socket2(connect_uuid)
            except ConnectionError:
                logger.debug("connect error")
            gevent.sleep(1)
        gevent.killall(self.thread_list)

    def parse_server_socket2(self, connect_uuid):
        server_socket2 = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        server_socket2_helper = SocketHelper(server_socket2)
        server_socket2.settimeout(self.socket_timeout)
        server_socket2.connect((self.ip, self.port))
        self.cipher2 = self.cipher.clone()
        server_socket2_helper.write(self.cipher2.encrypt(b"ok"))
        data_buffer = server_socket2_helper.read()
        if not data_buffer:
            logger.debug("close the socket")
            server_socket2.close()
            return
        first_data = self.cipher2.decrypt(data_buffer)
        logger.debug("received:%s" % first_data)
        if first_data != b'ok':
            logger.debug("close the socket")
            server_socket2.close()
            return

        json_data = {"type": "from_uuid", "connect_uuid": connect_uuid}
        json_data = json.dumps(json_data)
        logger.debug("send:%s" % json_data)
        json_data = self.cipher2.encrypt(json_data)
        server_socket2_helper.write(json_data)
        data_buffer = server_socket2_helper.read()
        json_data = self.cipher2.decrypt(data_buffer)
        logger.debug("received:%s" % json_data)
        json_data = json.loads(json_data)
        if json_data["data_type"] != "accept":
            logger.debug("close the socket")
            server_socket2.close()
            return

        r = gevent.spawn(self.parse_server_socket2_read, server_socket2_helper)
        w = gevent.spawn(self.parse_server_socket2_write, server_socket2_helper)
        self.thread_list.append(r)
        self.thread_list.append(w)
        gevent.wait(self.thread_list, count=1)
        logger.debug("close the socket")
        server_socket2.close()
        gevent.killall([r, w])
        self.thread_list.remove(r)
        self.thread_list.remove(w)

    def parse_server_socket2_read(self, server_socket2_helper):
        while True:
            try:
                # logger.debug("waiting for data")
                data_buffer = server_socket2_helper.read()
                c_data = self.cipher2.decrypt(data_buffer)
                # logger.debug("received:%s" % c_data)
                if c_data == PING_BYTES:
                    data = PONG_BYTES
                    data = self.cipher2.encrypt(data)
                    self.server_socket2_write_queue.put((CONTROL_PRIORITY, data))
                    continue
                if c_data == PONG_BYTES:
                    logger.debug("received pong")
                    continue
                if c_data.startswith(DATA_BYTES):
                    c_data = c_data[LEN_DATA_BYTES:]
                    socket_uuid = '%032x' % int.from_bytes((c_data[:16]), 'big')
                    # logger.debug(socket_uuid)
                    data = c_data[16:]
                    try:
                        upstream_write_queue = self.upstream_write_queue_dict[socket_uuid]
                        upstream_write_queue.put(data)
                    except KeyError:
                        logger.debug("KeyError!")
                    continue
                if c_data.startswith(FINISH_WRITE_SOCKET_BYTES):
                    # logger.debug("received:%s" % c_data)
                    c_data = c_data[LEN_FINISH_WRITE_SOCKET_BYTES:]
                    socket_uuid = '%032x' % int.from_bytes((c_data[:16]), 'big')
                    # logger.debug(socket_uuid)
                    try:
                        server_write_queue = self.upstream_write_ok_queue_dict[socket_uuid]
                        server_write_queue.put(True)
                    except KeyError:
                        logger.debug("KeyError!")
                    continue
                if c_data.startswith(b'{'):
                    c_json = json.loads(c_data)
                    data_type = c_json["type"]
                    if data_type == "new_socket":
                        logger.debug("received:%s" % c_data)
                        socket_uuid = c_json["socket_uuid"]
                        self.thread_list.append(gevent.spawn(self.parse_new_connect_to_upstream, socket_uuid))
                        continue
                    elif data_type == "close_socket":
                        logger.debug("received:%s" % c_data)
                        socket_uuid = c_json["socket_uuid"]
                        try:
                            upstream_socket = self.upstream_socket_dict[socket_uuid]
                            upstream_socket.close()
                        except KeyError:
                            pass
                        except:
                            logger.exception("error")
                        logger.debug("finish close_socket")
                        continue
                    elif data_type == "finish_write_socket":
                        # logger.debug("received:%s" % c_data)
                        socket_uuid = c_json["socket_uuid"]
                        try:
                            server_write_queue = self.upstream_write_ok_queue_dict[socket_uuid]
                            server_write_queue.put(True)
                        except KeyError:
                            logger.debug("KeyError!")
                        continue
                    elif data_type == "data":
                        socket_uuid = c_json["socket_uuid"]
                        data = server_socket2_helper.read()  # c_json["data"]
                        data = self.cipher2.decrypt(data)
                        # data = base85_decode(data, return_type=bytes)
                        # logger.debug(data)
                        try:
                            upstream_write_queue = self.upstream_write_queue_dict[socket_uuid]
                            upstream_write_queue.put(data)
                        except KeyError:
                            logger.debug("KeyError!")
                        continue
                logger.debug("received:%s" % c_data)
            except ConnectionError:
                logger.debug("server closed the connect")
                break
            except OSError as e:
                logger.debug(e.strerror)
                break
            except gevent.GreenletExit:
                break
            except ValueError:
                pass
            except KeyError:
                pass
        logger.debug("exit")

    def parse_server_socket2_write(self, server_socket2_helper):
        try:
            while True:
                try:
                    _, c_data = self.server_socket2_write_queue.get(timeout=self.socket_timeout / 2)
                    # logger.debug("send:%s" % c_data)
                    if c_data is None:
                        break
                except Empty:
                    c_data = PING_BYTES
                    logger.debug("send ping")
                    c_data = self.cipher2.encrypt(c_data)
                if isinstance(c_data, (list, tuple)):
                    for item in c_data:
                        # item = self.cipher2.encrypt(item)
                        server_socket2_helper.write(item)
                else:
                    # c_data = self.cipher2.encrypt(c_data)
                    server_socket2_helper.write(c_data)
        except _socket.timeout:
            logger.debug("timeout")
            pass
        except ConnectionError:
            logger.debug("socket closed")
            pass
        except gevent.GreenletExit:
            logger.debug("green let exit")
            pass
        except gevent._socketcommon.cancel_wait_ex:
            logger.debug("socket closed")
            pass
        logger.debug("exit")

    def parse_new_connect_to_upstream(self, socket_uuid):
        upstream_socket = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        upstream_socket.connect((self.upstream_ip, self.upstream_port))
        upstream_socket_helper = SocketHelper(upstream_socket, parse_split_bytes=False)
        upstream_write_queue = Queue()
        upstream_write_ok_queue = Queue()
        self.upstream_write_queue_dict[socket_uuid] = upstream_write_queue
        self.upstream_write_ok_queue_dict[socket_uuid] = upstream_write_ok_queue
        self.upstream_socket_dict[socket_uuid] = upstream_socket
        r = gevent.spawn(self.parse_upstream_read, upstream_socket_helper, upstream_write_ok_queue, socket_uuid)
        w = gevent.spawn(self.parse_upstream_write, upstream_socket_helper, upstream_write_queue, socket_uuid)
        json_data = {"type": "finish_new_socket", "socket_uuid": socket_uuid}
        json_data = json.dumps(json_data)
        logger.debug("send:%s" % json_data)
        json_data = self.cipher2.encrypt(json_data)
        self.server_socket2_write_queue.put((CONTROL_PRIORITY, json_data))
        gevent.wait([r, w], count=1)
        gevent.killall([r, w])
        logger.debug("socket_uuid=%s exit" % socket_uuid)
        data = {"type": "close_socket", "socket_uuid": socket_uuid}
        data = json.dumps(data)
        logger.debug("send:%s" % data)
        data = self.cipher2.encrypt(data)
        self.server_socket2_write_queue.put((CONTROL_PRIORITY, json_data))
        self.upstream_socket_dict.pop(socket_uuid, None)
        upstream_socket.close()

    def parse_upstream_read(self, socket_helper: SocketHelper, upstream_write_ok_queue: Queue, socket_uuid: str):
        if upstream_write_ok_queue.empty():
            upstream_write_ok_queue.put(True)
        try:
            while True:
                data_buffer = socket_helper.read()
                # logger.debug("received:%s" % data_buffer)
                # data_buffer = base85_encode(data_buffer)

                # data = {"type": "data", "socket_uuid": socket_uuid}  # , "data": data_buffer}
                # data = json.dumps(data)
                # # logger.debug(data)
                # data = self.cipher2.encrypt(data)
                # data_buffer = self.cipher2.encrypt(data_buffer)
                # upstream_write_ok_queue.get()
                # self.server_socket2_write_queue.put((DATA_PRIORITY, (data, data_buffer)))

                data = DATA_BYTES + int(socket_uuid, 16).to_bytes(16, 'big') + data_buffer
                data = self.cipher2.encrypt(data)
                upstream_write_ok_queue.get()
                self.server_socket2_write_queue.put((DATA_PRIORITY, data))
        except _socket.timeout:
            pass
        except ConnectionError:
            pass
        except gevent.GreenletExit:
            pass
        except gevent._socketcommon.cancel_wait_ex:
            pass
        logger.debug("socket_uuid=%s exit" % socket_uuid)

    def parse_upstream_write(self, socket_helper: SocketHelper, server_queue: Queue, socket_uuid: str):
        try:
            while True:
                c_data = server_queue.get()
                if c_data is None:
                    break
                # logger.debug("send:%s" % c_data)
                socket_helper.write(c_data)
                # json_data = {"type": "finish_write_socket", "socket_uuid": socket_uuid}
                # json_data = json.dumps(json_data)

                json_data = FINISH_WRITE_SOCKET_BYTES + int(socket_uuid, 16).to_bytes(16, 'big')
                # logger.debug("send:%s" % json_data)
                json_data = self.cipher2.encrypt(json_data)
                # logger.debug("send:%s" % json_data)
                self.server_socket2_write_queue.put((FINISH_WRITE_SOCKET_PRIORITY, json_data))
        except _socket.timeout:
            pass
        except ConnectionError:
            pass
        except OSError:
            pass
        except gevent.GreenletExit:
            pass
        logger.debug("socket_uuid=%s exit" % socket_uuid)


def client_main(ip="127.0.0.1", port=10086, password="password", method=default_cipher_name,
                upstream_ip="127.0.0.1", upstream_port=2000,
                listen_ip="127.0.0.1", listen_port=12000):
    parser = ArgumentParser(description="SimpleReverseProxy Client")
    parser.add_argument('--ip', type=str, default=ip,
                        help="set server ip")
    parser.add_argument('--port', type=int, default=port,
                        help="set server port")
    parser.add_argument('--upstream_ip', type=str, default=upstream_ip,
                        help="set upstream ip")
    parser.add_argument('--upstream_port', type=int, default=upstream_port,
                        help="set upstream port")
    parser.add_argument('--listen_ip', type=str, default=listen_ip,
                        help="set listen ip")
    parser.add_argument('--listen_port', type=int, default=listen_port,
                        help="set listen port")
    parser.add_argument('--password', type=str, default=password,
                        help="the password used to connect")
    parser.add_argument('--method', type=str, default=method,
                        help="the encrypt method used to connect")
    args = parser.parse_args()
    logger.info("start client connect to %s:%d" % (ip, port))
    client = ReverseProxyClient(args.ip, args.port, args.password, args.method, args.upstream_ip, args.upstream_port,
                                args.listen_ip, args.listen_port)
    client()
