"""
@File    :   app_rpdp.py
@Time    :   2023/07/24
@Version :   0.1

@Desc    :   the app_rpdp.py is responsible for RPDP-SAV rule generation
             In this implementation, the SPA and SPD is encoded into standard BGP Update message
"""

import grpc
from control_plane import agent_msg_pb2, agent_msg_pb2_grpc
from common.sav_common import *
from urllib.parse import urlparse
from aioquic.asyncio.protocol import QuicConnectionProtocol
import threading
import asyncio
import json
import time
from collections import deque
from typing import BinaryIO, Callable, Deque, Dict, List, Optional, cast

import aioquic
import wsproto
import wsproto.events
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

USER_AGENT = "aioquic/" + aioquic.__version__
GRPC_RETRY_INTERVAL = 0.1


class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)

        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme


class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[Dict] = None,
    ) -> None:
        if headers is None:
            headers = {}

        self.content = content
        self.headers = headers
        self.method = method
        self.url = url


class WebSocket:
    def __init__(
        self, http: H3Connection, stream_id: int, transmit: Callable[[], None]
    ) -> None:
        self.http = http
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.stream_id = stream_id
        self.subprotocol: Optional[str] = None
        self.transmit = transmit
        self.websocket = wsproto.Connection(wsproto.ConnectionType.CLIENT)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        """
        Perform the closing handshake.
        """
        data = self.websocket.send(
            wsproto.events.CloseConnection(code=code, reason=reason)
        )
        self.http.send_data(stream_id=self.stream_id,
                            data=data, end_stream=True)
        self.transmit()

    async def recv(self) -> str:
        """
        Receive the next message.
        """
        return await self.queue.get()

    async def send(self, message: str) -> None:
        """
        Send a message.
        """
        assert isinstance(message, str)

        data = self.websocket.send(wsproto.events.TextMessage(data=message))
        self.http.send_data(stream_id=self.stream_id,
                            data=data, end_stream=False)
        self.transmit()

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            for header, value in event.headers:
                if header == b"sec-websocket-protocol":
                    self.subprotocol = value.decode()
        elif isinstance(event, DataReceived):
            self.websocket.receive_data(event.data)

        for ws_event in self.websocket.events():
            self.websocket_event_received(ws_event)

    def websocket_event_received(self, event: wsproto.events.Event) -> None:
        if isinstance(event, wsproto.events.TextMessage):
            self.queue.put_nowait(event.data)


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http: Optional[H3Connection] = None
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._websockets: Dict[int, WebSocket] = {}

        self._http = H3Connection(self._quic)

    async def get(self, url: str, headers: Optional[Dict] = None) -> Deque[H3Event]:
        """
        Perform a GET request.
        """
        return await self._request(
            HttpRequest(method="GET", url=URL(url), headers=headers)
        )

    async def post(
        self, url: str, data: bytes, headers: Optional[Dict] = None
    ) -> Deque[H3Event]:
        """
        Perform a POST request.
        """
        return await self._request(
            HttpRequest(method="POST", url=URL(url),
                        content=data, headers=headers)
        )

    async def websocket(
        self, url: str, subprotocols: Optional[List[str]] = None
    ) -> WebSocket:
        """
        Open a WebSocket.
        """
        request = HttpRequest(method="CONNECT", url=URL(url))
        stream_id = self._quic.get_next_available_stream_id()
        websocket = WebSocket(
            http=self._http, stream_id=stream_id, transmit=self.transmit
        )

        self._websockets[stream_id] = websocket

        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", request.url.authority.encode()),
            (b":path", request.url.full_path.encode()),
            (b":protocol", b"websocket"),
            (b"user-agent", USER_AGENT.encode()),
            (b"sec-websocket-version", b"13"),
        ]
        if subprotocols:
            headers.append(
                (b"sec-websocket-protocol", ", ".join(subprotocols).encode())
            )
        self._http.send_headers(stream_id=stream_id, headers=headers)

        self.transmit()

        return websocket

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(
                        self._request_events.pop(stream_id))

            elif stream_id in self._websockets:
                # websocket
                websocket = self._websockets[stream_id]
                websocket.http_event_received(event)

            elif event.push_id in self.pushes:
                # push
                self.pushes[event.push_id].append(event)

        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def _request(self, request: HttpRequest) -> Deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.authority.encode()),
                (b":path", request.url.full_path.encode()),
                (b"user-agent", USER_AGENT.encode()),
            ]
            + [(k.encode(), v.encode()) for (k, v) in request.headers.items()],
            end_stream=not request.content,
        )
        if request.content:
            self._http.send_data(
                stream_id=stream_id, data=request.content, end_stream=True
            )

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)


def write_response(
    http_events: Deque[H3Event], output_file: BinaryIO, include: bool
) -> None:
    for http_event in http_events:
        if isinstance(http_event, HeadersReceived) and include:
            headers = b""
            for k, v in http_event.headers:
                headers += k + b": " + v + b"\r\n"
            if headers:
                output_file.write(headers + b"\r\n")
        elif isinstance(http_event, DataReceived):
            output_file.write(http_event.data)


# def save_session_ticket(ticket: SessionTicket) -> None:
#     """
#     Callback which is invoked by the TLS engine when a new session ticket
#     is received.
#     """
#     logger.info("New session ticket received")
#     if args.session_ticket:
#         with open(args.session_ticket, "wb") as fp:
#             pickle.dump(ticket, fp)

# class QuicClientManager():
#     """establish quic connection and reuse it for sending"""
#     def __init__(self) -> None:
#         self.connections = {}
#         self.config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
#         self.config.load_verify_locations(r'/root/savop/ca_cert.pem')
#     def send(self,msg,url,host):
#         try:
#             if host in self.connections:
#                 asyncio.run(self.__quic_send(
#                     host, configuration, msg, url), debug=True)
#         except Exception as e:
#             self.logger.exception(e)
#             self.logger.error(e)
#             self.logger.error(type(e))
#         t = time.time()-t0
#         if t > TIMEIT_THRESHOLD:
#             self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")


class RPDPApp(SavApp):
    """
    a sav app implementation based on reference router (based on bird)
    embedded grpc link
    """

    def __init__(self, agent, name="rpdp_app", logger=None):
        super(RPDPApp, self).__init__(agent, name, logger)
        self.pp_v4_dict = {}
        self.connect_objs = {}
        self.metric = self.get_init_metric_dict()
        self.quic_config = QuicConfiguration(
            is_client=True, alpn_protocols=H3_ALPN)
        self.quic_config.load_verify_locations(r'/root/savop/ca_cert.pem')
        self.stub_dict = {}
        self.spa_data = {"inter": {}, "intra": {}}
        self.spd_data = {"inter": {}, "intra": {}}
        # local rule cache
        self.spd_sn_dict = {}
    def get_init_metric_dict(self):
        return {
            "dsav": init_protocol_metric(),
            "grpc": init_protocol_metric(),
            "quic": init_protocol_metric()
        }

    def get_pp_v4_dict(self):
        # retrun the bird prefix-(AS)path table in RPDPApp (no refreshing)
        return self.pp_v4_dict

    def _get_prefix_as_paths(self):
        """
        using current remote_fib to generate prefix-as_paths table
        """
        cur_fib = self.agent.bird_man.get_remote_fib()
        ret = {}
        for prefix,srcs in cur_fib.items():
            # self.logger.debug(prefix)
            for src in srcs:
                if src['as_path'] ==[]:
                    continue
                if prefix not in ret:
                    ret[prefix] = []
                ret[prefix].append(src['as_path'])
        return ret
    def diff_pp_v4(self, reset=False):
        """
        return adds and dels,
        which is a list of modification required(tuple of (prefix,path))
        if reset is True, will use empty dict as old_
        """
        t0 = time.time()
        if reset:
            self.pp_v4_dict = {}
        old_ = self.pp_v4_dict
        new_ = self._get_prefix_as_paths()
        # self.logger.debug(f"new_ {new_}")
        dels = []
        adds = []
        # self.logger.debug(new_)
        # self.logger.debug(old_)
        for prefix, paths in new_.items():
            if prefix not in old_:
                # self.logger.debug(paths)
                for path in paths:
                    adds.append((prefix, path))
            else:
                if paths != old_[prefix]:
                    for path in old_[prefix]:
                        if not path in paths:
                            dels.append((prefix, path))
                    for path in new_[prefix]:
                        if not path in old_[prefix]:
                            adds.append((prefix, path))
        for prefix in old_:
            if prefix not in new_:
                for path in old_[prefix]:
                    dels.append((prefix, path))
        self.pp_v4_dict = new_
        # self.logger.debug(adds)
        # self.logger.debug(dels)
        t = time.time()-t0
        if t > TIMEIT_THRESHOLD:
            self.logger.warning(f"TIMEIT {time.time()-t0:.4f} seconds")
        return adds, dels

    def reset_metric(self):
        self.metric = self.get_init_metric_dict()

    def _build_inter_sav_spa_nlri(self, origin_asn, prefix, route_type=2, flag=1):
        return (route_type, origin_asn, prefix, flag)


    def _add_metric(self, msg, in_time, process_time, link_type, direction):
        self.metric[link_type][direction]["count"] += 1
        self.metric[link_type][direction]["size"] += len(str(msg))
        self.metric[link_type][direction]["time"] += process_time
        if self.metric[link_type]["start"] is None:
            self.metric[link_type]["start"] = in_time
        self.metric[link_type]["end"] = in_time+process_time

    def send_msg(self, msg, config, link):
        """send msg to other sav agent"""
        t0 = time.time()
        # self.logger.debug(f"sending {msg}")
        # self.logger.debug(f"link: {link}")
        try:
            map_data = {}
            link_name = link["protocol_name"]
            if link_name in config["link_map"]:
                link_type = config["link_map"][link_name]["link_type"]
                map_data = config["link_map"][link_name]["link_data"]
            else:
                link_type = link["link_type"]

            if link_type == "grpc":
                self._send_grpc(msg, config["router_id"], map_data)
            elif link_type == "dsav":
                # using reference router
                self._send_dsav(msg)
            elif link_type == "quic":
                a = threading.Thread(target=self._send_quic, args=(
                    msg, link, self.quic_config))
                # a.setDaemon(True)
                a.start()
                a.join()
            elif link_type == "native_bgp":
                # this should not happen
                self.logger.error(link)
                self.logger.error(msg)
            else:
                self.logger.error(f"unhandled msg {msg}")
            t = time.time()
            # self.logger.debug(f"sending {link_type} took {t-t0:.4f} seconds")
            process_time = t-t0
            if process_time > TIMEIT_THRESHOLD:
                self.logger.warning(f"TIMEIT {t:.4f} seconds")
            # self._add_metric(msg, t0, process_time, link_type, "send")
        except Exception as e:
            self.logger.exception(e)
            self.logger.error(e)
            self.logger.error(f"sending [{msg}] error")

    def _quic_msg_box(self, msg, bgp_meta):
        msg["sav_nlri"] = list(map(prefix2str, msg["sav_nlri"]))
        msg["dummy_link"] = f"savbgp_{bgp_meta['remote_as']}_{bgp_meta['local_as']}"
        return json.dumps(msg)

    def _quic_msg_unbox(self, msg):
        link_meta = self.agent.link_man.get_by_name(
            msg["source_link"])
        msg["msg"]["interface_name"] = link_meta["interface_name"]
        msg["msg"]["as_path"] = msg["msg"]["sav_path"]
        return msg

    async def __quic_send(self, host, configuration, msg, url):
        # self.logger.debug(host)
        # self.logger.debug(url)
        try:
            async with connect(
                host,
                7777,
                configuration=configuration,
                create_protocol=HttpClient,
                session_ticket_handler=None,
                local_port=0,
                wait_connected=True,
            ) as client:
                client = cast(HttpClient, client)
                ws = await client.websocket(url, subprotocols=["chat", "superchat"])

                await ws.send(msg)
                rep = await ws.recv()
                if not rep == "good":
                    self.logger.debug(rep)
                    self.logger.error("not good")
                await ws.close()
                client._quic.close(error_code=ErrorCode.H3_NO_ERROR)
        except Exception as e:
            self.logger.exception(e)
            self.logger.debug(f"connect {host} failed")
            self.logger.error(type(e))
            self.logger.error(dir(e))
            self.logger.debug(e.name())
            trace = e.with_traceback()
            # self.logger.error(str(e))
            self.logger.error(str(trace))
            self.logger.error(dir(trace))
            self.logger.error()

    async def __quic_send2(self, host, configuration, msg, url, connection=None):
        if connection is None:
            try:
                async with connect(
                    host,
                    7777,
                    configuration=configuration,
                    create_protocol=HttpClient,
                    session_ticket_handler=None,
                    local_port=0,
                    wait_connected=True,
                ) as client:
                    client = cast(HttpClient, client)
                    ws = await client.websocket(url, subprotocols=["chat", "superchat"])
                    await ws.send(msg)
                    rep = await ws.recv()
                    if not rep == "good":
                        self.logger.debug(rep)
                        self.logger.error("not good")
                    connection = {"client": client, "ws": ws}
                # await ws.close()
                # client._quic.close(error_code=ErrorCode.H3_NO_ERROR)
            except Exception as e:
                self.logger.exception(e)
                self.logger.debug(f"connect {host} failed")
                self.logger.error(type(e))
                self.logger.error(dir(e))
        else:
            ws = connection["ws"]
            await ws.send(msg)
            rep = await ws.recv()
            if not rep == "good":
                self.logger.debug(rep)
                self.logger.error("not good")

    def _send_quic(self, msg, bgp_meta, configuration):
        # self.logger.debug(msg)
        t0 = time.time()
        try:
            url = f"wss://node_{bgp_meta['remote_as']}:7777/savop_quic"
            host = bgp_meta["remote_ip"]
            msg = self._quic_msg_box(msg, bgp_meta)
            asyncio.run(self.__quic_send2(
                host, configuration, msg, url), debug=True)
        except Exception as e:
            self.logger.exception(e)
            self.logger.error(e)
            self.logger.error(type(e))
        t = time.time()-t0
        if t > TIMEIT_THRESHOLD:
            self.logger.debug(f"TIMEIT {time.time()-t0:.4f} seconds")

    def _send_grpc(self, msg, grpc_id, grpc_link):
        t0 = time.time()
        try:
            if isinstance(msg["sav_nlri"][0], netaddr.IPNetwork):
                msg["sav_nlri"] = list(map(prefix2str, msg["sav_nlri"]))
            remote_addr = grpc_link["remote_addr"]
            remote_ip = remote_addr.split(':')[0]
            remote_id = grpc_link["remote_id"]
            msg["dst_ip"] = remote_ip
            str_msg = json.dumps(msg)
            self.logger.debug(remote_addr)
            while True:
                try:
                    if not remote_addr in self.stub_dict:
                        channel = grpc.insecure_channel(remote_addr)
                        stub = agent_msg_pb2_grpc.AgentLinkStub(channel)
                        self.stub_dict[remote_addr] = stub
                    agent_msg = agent_msg_pb2.AgentMsg(
                        sender_id=grpc_id, json_str=str_msg)
                    rep = self.stub_dict[remote_addr].Simple(agent_msg)
                    expected_str = f"got {str_msg}"
                    if not rep.json_str == expected_str:
                        raise ValueError(
                            f"json expected {expected_str}, got {rep.json_str}")
                    if not rep.sender_id == remote_id:
                        self.logger.debug(
                            f"sending to {remote_addr},{remote_id}")
                        raise ValueError(
                            f"remote id expected {remote_id}, got {rep.sender_id}")
                    t = time.time()-t0
                    if t > TIMEIT_THRESHOLD:
                        self.logger.warning(
                            f"TIMEIT {time.time()-t0:.4f} seconds")
                    return True
                except Exception as e:
                    self.logger.exception(e)
                    self.logger.debug(msg)
                    self.logger.error(e)
                    self.logger.error(
                        f"grpc error, retrying in {GRPC_RETRY_INTERVAL} seconds")
                    time.sleep(GRPC_RETRY_INTERVAL)
        except Exception as e:
            self.logger.exception(e)
            self.logger.error(e)

    def perf_test_send(self, msgs):
        count = 0
        self.logger.debug("perf test send start")
        using_link = "savbgp_34224_3356"
        self.metric["perf_test"] = self.get_init_metric_dict()
        self.metric["perf_test"]["bgp"] = init_protocol_metric()
        for msg in msgs:
            count += 1
            t0 = time.time()
            match msg["msg_type"]:
                case "dsav":
                    self.agent.put_out_msg(msg)
                    self.agent.bird_man.bird_cmd("call_agent")
                case "bgp":
                    self.agent.put_out_msg(msg)
                    self.agent.bird_man.bird_cmd("call_agent")
                case "grpc":
                    link = self.agent.link_man.get_by_name(using_link)
                    self._send_grpc(msg["msg"],
                                    self.agent.config["router_id"],
                                    {"remote_addr": "10.0.0.1:5000",
                                     "remote_id": "10.0.0.1"})
                case "quic":
                    msg["msg"]["sav_nlri"] = list(
                        map(netaddr.IPNetwork, msg["msg"]["sav_nlri"]))
                    link = self.agent.link_man.get_link_meta_by_name(
                        using_link)
                    self.send_msg(msg["msg"], self.agent.config, link)
                case _:
                    self.logger.error(
                        f"unknown msg type {msg['msg_type']}({type(msg['msg_type'])})")
            process_time = time.time()-t0
            temp = self.metric["perf_test"][msg["msg_type"]]
            if temp["start"] is None:
                temp["start"] = t0
            temp["end"] = t0+process_time
            temp["send"]["count"] += 1
            temp["send"]["size"] += len(str(msg))
            temp["send"]["time"] += process_time
            self.metric["perf_test"][msg["msg_type"]] = temp
            self.logger.debug(f"SENT {count} msg ({msg['msg_type']})")
        self.logger.debug("perf test send finished")

    def _send_dsav(self, msg):
        """
        notify the bird to retrieve the msg from flask server and execute it.
        """
        # self.logger.debug(msg.keys())
        if not isinstance(msg, dict):
            self.logger.error(f"msg is not a dictionary msg is {type(msg)}")
            return
        # specialized for bird app, we need to convert the msg to byte array
        nlri = copy.deepcopy(msg["sav_nlri"])
        # split into multi mesgs
        max_nlri_len = 50
        while len(nlri) > 0:
            msg["sav_nlri"] = nlri[:max_nlri_len]
            msg_byte = self._msg_to_hex_str(msg)
            out_msg = {"msg_type": "dsav", "data": msg_byte,
                       "source_app": self.name, "timeout": 0, "store_rep": False}
            self.agent.put_out_msg(out_msg)
            nlri = nlri[max_nlri_len:]
        # self.logger.info(
            # f"SENT MSG ON LINK [{msg['protocol_name']}]:{msg}, time_stamp: [{time.time()}]]")

    def _msg_to_hex_str(self, msg):
        """
        msg is in json format,but bird is difficult to use,
        therefore we transfer the msg to byte array,
        and put that into the json for bird app
        """
        t0 = time.time()
        key_types = [("msg_type", str), ("protocol_name", str),
                     ("as4_session", bool), ("sav_nlri", list),
                     ("is_interior", bool), ("is_native_bgp", int)]
        try:
            keys_types_check(msg, key_types)
        except Exception as e:
            self.logger.exception(e)
            self.logger.error(e)
            return None

        hex_str_msg = {"is_native_bgp": msg["is_native_bgp"]}
        is_as4 = msg["as4_session"]
        hex_str_msg["sav_nlri"] = prefixes2hex_str(msg["sav_nlri"])
        hex_str_msg["nlri_len"] = len(decode_csv(hex_str_msg["sav_nlri"]))
        m_t = msg["msg_type"]
        hex_str_msg["protocol_name"] = msg["protocol_name"]
        hex_str_msg["next_hop"] = msg["src"].split(".")
        hex_str_msg["next_hop"] = [
            str(len(hex_str_msg["next_hop"]))] + hex_str_msg["next_hop"]
        hex_str_msg["next_hop"] = ",".join(hex_str_msg["next_hop"])
        # self.logger.debug(msg["sav_scope"])
        hex_str_msg["sav_scope"] = scope_to_hex_str(
            msg["sav_scope"], msg["is_interior"], is_as4)
        # self.logger.debug(hex_str_msg["sav_scope"] )
        hex_str_msg["is_interior"] = 1 if msg["is_interior"] else 0
        if msg["is_interior"]:
            as_path_code = "2"
            hex_str_msg["withdraws"] = "0,0"
            hex_str_msg["sav_origin"] = ",".join(int2hex(
                msg["sav_origin"], is_as4))
            if m_t == "origin":
                # insert origin for sav
                # using ba_origin, there is no need to convert tot as4
                hex_str_msg["as_path"] = ",".join(
                    [as_path_code, "1", hex_str_msg["sav_origin"]])
                hex_str_msg["as_path_len"] = len(
                    decode_csv(hex_str_msg["as_path"]))
                # insert asn_paths
                t = time.time()-t0
                if t > TIMEIT_THRESHOLD:
                    self.logger.warning(f"TIMEIT {time.time()-t0:.4f} seconds")
                return hex_str_msg
            elif m_t == "relay":
                as_number = str(len(msg["sav_path"]))
                temp = path2hex(msg["sav_path"], is_as4)
                hex_str_msg["as_path"] = ",".join(
                    [as_path_code, as_number]+temp)
                hex_str_msg["as_path_len"] = len(
                    decode_csv(hex_str_msg["as_path"]))
                t = time.time()-t0
                if t > TIMEIT_THRESHOLD:
                    self.logger.warning(f"TIMEIT {time.time()-t0:.4f} seconds")
                return hex_str_msg
            else:
                self.logger.error(f"unknown msg_type: {m_t}")

        else:
            hex_str_msg["withdraws"] = "0,0"
            hex_str_msg["sav_origin"] = ",".join(
                ipv4_str_to_hex(msg["sav_origin"]))
            t = time.time()-t0
            if t > TIMEIT_THRESHOLD:
                self.logger.warning(f"TIMEIT {time.time()-t0:.4f} seconds")
            return hex_str_msg

    def _construct_msg(self, link, input_msg, msg_type, is_inter):
        """
        construct a message for apps to use,
        if msg_type is origin, input_msg is the value of sav_scope list of paths
        if msg_type is relay, input_msg a dict include sav_path, sav_nlri, sav_origin, sav_scope
        """
        # self.logger.debug(
        # f"link:{link},input_msg:{input_msg},msg_type:{msg_type},is_inter:{is_inter}")
        try:
            msg = {
                "src": str(link["local_ip"]),
                "dst": str(link["remote_ip"]),
                "msg_type": msg_type,
                "is_interior": is_inter,
                "as4_session": link["as4_session"],
                "protocol_name": link["protocol_name"],
                "is_native_bgp": 0
            }
            spd_msg = {}
            if link["link_type"] == "grpc":
                msg["dst_id"] = link["remote_id"]
                msg["src_id"] = self.agent.config["grpc_config"]["id"]
            if msg_type == "origin":
                if is_inter:
                    msg["sav_origin"] = self.agent.config["local_as"]
                    msg["sav_scope"] = input_msg
                else:
                    msg["sav_origin"] = link["router_id"]
                msg["sav_path"] = [msg["sav_origin"]]
                msg["sav_nlri"] = self.agent.get_local_prefixes()
            elif msg_type == "relay":
                msg["sav_origin"] = input_msg["sav_origin"]
                msg["sav_nlri"] = input_msg["sav_nlri"]
                msg["sav_path"] = input_msg["sav_path"]
                msg["sav_scope"] = input_msg["sav_scope"]
            else:
                self.logger.error(f"unknown msg_type:{msg_type}\nmsg:{msg}")
            # filter send empty sav_scope
            temp = []
            for path in msg["sav_scope"]:
                if len(path) > 0:
                    temp.append(path)
            msg["sav_scope"] = temp
            msg["sav_origin"] = str(msg["sav_origin"])
            # if check_agent_agent_msg(msg):
            return msg
        except Exception as e:
            self.logger.exception(e)
            self.logger.error(e)
            self.logger.error("construct msg error")

    # def recv_http_msg(self, msg):
    #     adds = []
    #     try:
    #         m_t = msg["msg_type"]
    #         if not m_t in ["bird_bgp_config", "bgp_update"]:
    #             raise ValueError(f"unknown msg_type: {m_t} received via http")
    #         if "rpdp" in msg["msg"]["channels"]:
    #             link_type = "dsav"
    #         else:
    #             link_type = "native_bgp"
    #         msg["source_app"] = self.name
    #         msg["source_link"] = msg["msg"]["protocol_name"]

    #         if m_t == "bgp_update":
    #             self.put_link_up(msg["source_link"], link_type)
    #             msg["msg"] = self.preprocess_msg(msg["msg"])
    #             # self.logger.debug("receive_http_msg")
    #             adds = self.process_rpdp_spa_msg(msg)
    #         else:
    #             self.logger.error(msg)
    #             self.agent.put_msg(msg)
    #     except Exception as e:
    #         self.logger.exception(e)
    #         self.logger.error(e)
    #     return adds

    def process_grpc_msg(self, msg):
        # self.logger.debug(msg)
        link_meta = self.agent.link_man.get_by_name(
            msg["source_link"])
        while link_meta is None:
            self.logger.debug(f"link_meta is None, updating protos")
            link_meta = self.agent.link_man.get_by_name(msg["source_link"])

        msg["msg"]["interface_name"] = link_meta["interface_name"]
        msg["link_type"] = "grpc"
        return self.process_rpdp_spa_msg(msg)

    def process_quic_msg(self, msg, is_test_msg=False, test_id=None):
        self.logger.debug("enter")
        msg = self._quic_msg_unbox(msg)
        self.logger.debug("unboxed")
        return self.process_rpdp_spa_msg(msg)

    def preprocess_msg(self, msg):
        # as_path is easier to process in string format, so we keep it
        # process routes
        msg["routes"] = decode_csv(input_str=msg["routes"])
        msg["add_routes"] = []
        msg["del_routes"] = []
        for route in msg["routes"]:
            if route[0] == "+":
                msg["add_routes"].append(netaddr.IPNetwork(route[1:]))
            elif route[0] == "-":
                msg["del_routes"].append(netaddr.IPNetwork(route[1:]))
        del msg["routes"]
        # process sav_nlri
        msg["sav_nlri"] = hex_str_to_prefixes(msg["sav_nlri"])
        # process sav_scope
        msg["sav_scope"] = str_to_scope(msg["sav_scope"])
        # process as_path, only used for inter-msgs
        msg["as_path"] = decode_csv(msg["as_path"])
        return msg

    def process_rpdp_inter(self, msg, link):
        """
        determine whether to relay or terminate the message.
        """
        # self.logger.debug(f"process rpdp inter msg {msg}, link {link}")
        link_meta = link
        scope_data = msg["sav_scope"]
        # self.logger.debug(scope_data)
        relay_msg = {
            "sav_nlri": msg["sav_nlri"],
            "sav_origin": msg["sav_origin"]
        }
        new_path = msg["sav_path"]+[self.agent.config["local_as"]]
        for i in range(len(new_path)-1):
            self.agent.add_sav_link(new_path[i], new_path[i+1])
        # self.agent._log_info_for_front(msg=None, log_type="sav_graph")
        relay_scope = {}
        intra_links = self.agent.link_man.get_up_intra_links()
        # if we receive a inter-domain msg via inter-domain link
        # self.logger.debug(msg["sav_scope"])
        if link_meta["is_interior"]:
            for path in scope_data:
                # self.logger.debug(path)
                next_as = int(path.pop(0))  # for modified bgp
                if (self.agent.config["local_as"] != next_as):
                    self.logger.debug(msg["sav_scope"])
                    path.append(next_as)
                    self.logger.error(
                        f"as number mismatch msg:{path} local_as {self.agent.config['local_as']},next_as {next_as}")
                    return
                if len(path) == 0:
                    # self.agent._log_info_for_front(msg, "terminate")
                    # AS_PATH:{msg['sav_path']} at AS {m['local_as']}")
                    for link_name in intra_links:
                        link = self.agent.link_man.get_by_name(link_name)
                        relay_msg["sav_path"] = msg["sav_path"]
                        relay_msg["sav_scope"] = scope_data
                        # self.logger.debug(scope_data)
                        relay_msg = self._construct_msg(
                            link, relay_msg, "relay", True)
                        relay_msg['sav_nlri'] = list(
                            map(str, relay_msg['sav_nlri']))
                        self.agent._log_info_for_front(
                            msg, "relay_terminate", link_name)
                else:
                    # self.logger.debug(path)
                    # self.logger.debug(relay_scope)
                    if path[0] in relay_scope:
                        # TODO here we may add incorrect AS(AS that we donnot have SAV link)
                        relay_scope[path[0]].append(path)
                    else:
                        relay_scope[path[0]] = [path]
        # if we receive a inter-domain msg via intra-domain link
        else:
            self.logger.error("THIS SHOULD NOT HAPPEN ,no msg should be intra")
            if len(scope_data) > 0:
                # in demo we only rely this to inter-links
                for path in scope_data:
                    if path[0] in relay_scope:
                        relay_scope[path[0]].append(path)
                    else:
                        relay_scope[path[0]] = [path]
            else:
                # if receiving inter-domain msg via intra-domain link
                # and there is no scope data, it means we terminate the msg here
                return
        # self.logger.debug(relay_scope)
        for next_as, sav_scope in relay_scope.items():
            inter_links = self.agent.bird_man.get_by_remote_as_is_inter(
                next_as, True)
            # self.logger.debug(inter_links)
            # native_bgp link may included
            inter_links_temp = []
            for i in inter_links:
                if i["link_type"] == "dsav":
                    inter_links_temp.append(i)
                else:
                    if i["protocol_name"] in self.agent.config["link_map"]:
                        inter_links_temp.append(i)
            inter_links = inter_links_temp
            # self.logger.debug(inter_links)
            # self.logger.debug(sav_scope)
            relay_msg["sav_scope"] = sav_scope
            relay_msg["sav_path"] = msg["sav_path"] + \
                [self.agent.config["local_as"]]
            for link in inter_links:
                relay_msg["sav_scope"] = sav_scope
                relay_msg = self._construct_msg(
                    link, relay_msg, "relay", True)
                self.send_msg(relay_msg, self.agent.config, link)
            if link_meta["is_interior"] and msg["is_interior"]:
                for link_name in intra_links:
                    link = self.agent.bird_man.get_link_meta_by_name(link_name)
                    relay_msg = self._construct_msg(
                        link, relay_msg, "relay", True)
                    self.send_msg(relay_msg, self.agent.config, link)
            if len(inter_links) == 0:
                if link_meta["is_interior"]:
                    self.logger.debug(
                        f"unable to find interior link for as: {next_as}, no SAV ?")

    def process_rpdp_spa_msg(self, msg):
        """
        process rpdp message, only inter-domain is supported
        regarding the nlri part, the processing procedure is the same
        """
        # t0 = time.time()
        # self.logger.debug(msg)
        link_name = msg["source_link"]
        is_interior = self.agent.link_man.get_by_name(link_name)["is_interior"]
        result = []
        temp = msg["msg"]
        v = None
        if 'rpdp6' in msg['msg']['channels']:
            v = 6
        if 'rpdp4' in msg['msg']['channels']:
            if v == 6:
                raise ValueError("both rpdp4 and rpdp6 in channels")
            v = 4
        for i in [temp["spa_add"], temp["spa_del"]]:
            # self.logger.debug(i)
            # self.logger.debug(v)
            if is_interior:
                result.append(read_inter_spa_nlri_hex(i, v))
            else:
                result.append(read_intra_spa_nlri_hex(i, v))
        adds, dels = result
        self.logger.debug(f"adds: {adds}")
        self.logger.debug(f"dels: {dels}")
        link_meta = self.agent.link_man.get_by_name(msg["source_link"])
        is_inter = link_meta["is_interior"]
        if is_inter:
            data = self.spa_data["inter"]
        else:
            data = self.spa_data["intra"]
        for d in adds:
            if is_inter:
                k = d["origin_asn"]
            else:
                k = netaddr.IPAddress(d["origin_router_id"])
            if not k in data:
                data[k] = {}
            # self.logger.debug(d)
            data[k][d["prefix"]] = d
        for d in dels:
            if is_inter:
                k = d["origin_asn"]
                k2 = d["prefix"]
            else:
                k = netaddr.IPAddress(d["origin_router_id"])
                k2 = d["prefix"]
            try:
                del data[k][k2]
            except KeyError:
                self.logger.debug(data)
                self.logger.debug(k)
                self.logger.debug(k2)
                self.logger.warning("key error")
        if is_inter:
            self.spa_data["inter"] = data
        else:
            self.spa_data["intra"] = data
        self.logger.debug(self.spa_data)
        self._refresh_sav_rules()
    def _find_prefix_in_spa(self, prefix, is_inter):
        if is_inter:
            data = self.spa_data["inter"]
        else:
            data = self.spa_data["intra"]
            raise NotImplementedError
        for asn, prefixes in data.items():
            pass
    def _get_spd_sn(self, dst):
        """
        dst could be an ip address or an asn
        """
        if not dst in self.spd_sn_dict:
            self.spd_sn_dict[dst] = 0
        else:
            self.spd_sn_dict[dst] += 1
        if self.spd_sn_dict[dst]> 4294967295:  # max int for IPV4
            self.spd_sn_dict[dst] = 0
        return self.spd_sn_dict[dst]
    def _get_spd_key(self,peer_ip,is_inter,peer_asn=None):
        ret = f"{peer_ip.value}"
        if is_inter:
            ret += f"{peer_asn}"
        return ret
    def send_spd(self,remote_links, as_neighbors ,my_as_prefixes,my_asn,my_router_id):
        """
        send inter-as spds on remote_links
        send intra-as spds on my_as_prefixes
        """

        # send intra-as spds
        # self.logger.debug(remote_links)
        # self.logger.debug(as_neighbors)
        self.logger.debug(my_as_prefixes)
        timeout = 0
        # send inter-as spds
        # for inter-as spd,we only send to the neighbor that we have a sav link
        is_interior = True
        for link_name,link_meta in remote_links.items():
            # self.logger.debug(link_meta)
            
            ip_version = link_meta["remote_ip"].version
            peer_as = link_meta["remote_as"]
            if not peer_as in as_neighbors:
                as_neighbors[peer_as] = []
            try:
                data = get_bird_spd_data(protocol_name=link_name
                                            ,channel="rpdp"
                                            ,rpdp_version=ip_version
                                            ,sn=self._get_spd_sn(self._get_spd_key(link_meta['remote_ip'],is_interior,peer_as))
                                            ,origin_router_id=my_router_id
                                            ,opt_data=[]
                                            ,is_interior=is_interior
                                            ,my_as=my_asn
                                            ,peer_as=peer_as
                                            ,peer_neighbor_as_list=as_neighbors[peer_as]
                                            )
                
                msg = get_agent_bird_msg(
                    data,link_meta["link_type"], self.name, timeout, False)
                # self.logger.debug(msg)
                self.agent.link_man.put_send_async(msg)
            except Exception as e:
                self.logger.exception(e)
                self.logger.error(e)
        is_interior = False
        intra_to_go_data = {}
        # aggregate the dst ip by next hop ip
        for prefix,prefix_data in my_as_prefixes.items():
            # self.logger.debug(f"prefix: {prefix}, prefix_data: {prefix_data}")
            dst_ip = prefix.network +1
            ip_version = dst_ip.version
            try:
                self.agent.link_man.get_by_local_ip(dst_ip)
                continue
            except ValueError:
                pass
            link_meta = self.agent.get_next_link_meta(dst_ip)
            if link_meta is None:
                self.logger.warning(f"no link for {dst_ip}")
                continue
            if not link_meta["protocol_name"] in intra_to_go_data:
                intra_to_go_data[link_meta["protocol_name"]] = {"link_meta":link_meta,"addresses": []}
            intra_to_go_data[link_meta["protocol_name"]]["addresses"].append(dst_ip)
        for link_name,link_data in intra_to_go_data.items():
            link_meta = link_data["link_meta"]
            addresses = link_data["addresses"]
            try:
                data = get_bird_spd_data(protocol_name=link_meta["protocol_name"]
                                        ,channel=f"rpdp{ip_version}"
                                        ,rpdp_version=ip_version
                                        ,sn=self._get_spd_sn(self._get_spd_key(dst_ip,is_interior))
                                        ,origin_router_id=my_router_id
                                        ,opt_data=[]
                                        ,is_interior=is_interior
                                        ,addresses=addresses)
                msg = get_agent_bird_msg(
                        data,link_meta["link_type"], self.name, timeout, False)
                # self.logger.debug(msg)
                self.agent.link_man.put_send_async(msg)
            except Exception as e:
                self.logger.exception(e)
                self.logger.error(e)

        
    def _spd_sn_check(self, sn, link_name):
        """
        return True if we need to process this message
        """
        link_meta = self.agent.link_man.get_by_name(link_name)
        if not "spd_sn" in link_meta:
            self.agent.link_man.update_link_kv(link_name, "spd_sn", sn)
            return True
        if sn == 0:
            self.agent.link_man.update_link_kv(link_name, "spd_sn", sn)
            return True
        if link_meta["spd_sn"] <= sn:
            self.agent.link_man.update_link_kv(link_name, "spd_sn", sn)
            return True
        else:
            self.logger.info(
                f"spd sn check failed, processed sn {link_meta['spd_sn']}, received sn {sn},ignore")
            return False

    def process_rpdp_route_refresh(self, msg, link_meta):
        """
        process rpdp route refresh message
        """
        # self.logger.debug(msg)
        if not self._spd_sn_check(msg["msg"]["SN"], msg["source_link"]):
            self.logger.warning("spd_sn check failed")
            return
        spd_msg = msg["msg"]
        
        # process common fields
        origin_router_id = netaddr.IPAddress(spd_msg["origin_router_id"])
        proto_name = spd_msg["protocol_name"]
        sub_type = spd_msg["sub_type"]
        if  sub_type== 2:
            data = self.spd_data["inter"]
            if self.agent.config["local_as"] == spd_msg["source_asn"]:
                need_to_relay = False
            else:
                need_to_relay = True
                self.logger.debug("need to relay, we are not ready for this")
            new_ases = [spd_msg["source_asn"]]
            new_ases.extend(spd_msg["peer_neighor_asns"])
            for asn in new_ases:
                if not asn in data:
                    data[asn] = set()
                data[asn].add(proto_name)
            self.spd_data["inter"] = data
        elif sub_type == 1:
            data = self.spd_data["intra"]
            spd_msg["addresses"] = addresses2ips(spd_msg["addresses"], spd_msg["ip_version"])
            new_ips = [origin_router_id]
            for ip in spd_msg["addresses"]:
                try:
                    _ = self.agent.link_man.get_by_local_ip(ip)
                except ValueError:
                    new_ips.append(ip)
            for ip in new_ips:
                if not ip in data:
                    data[ip] = set()
                data[ip].add(proto_name)
            self.spd_data["intra"] = data
        else:
            self.logger.debug(msg)
            self.logger.error(f"unknown subtype: {spd_msg['subtype']}")

        # self.logger.debug(self.spd_data)
        self._refresh_sav_rules()

    def _send_spa_origin_inter(self, link_name, link_meta, prefixes):
        """
        send spa origin msg
        update the link_meta["initial_broadcast"] to True
        the prefixes must either be a ipv4 prefix or a ipv6 prefix
        """
        # send to all neighbors
        self.logger.debug(
            f"building spa origin on inter {link_name}:{prefixes}")
        spa_add = []
        spa_del = []  # when broadcasting, we don't delete any prefix
        prefix_version = None
        for p, p_data in prefixes.items():
            # self.logger.debug(f"p: {p}, data: {p_data}")
            # self.logger.debug(self.agent.config)
            hex_data = get_inter_spa_nlri_hex(
                self.agent.config["local_as"],
                p,
                0,  # flag
            )
            # self.logger.debug(hex_data)
            spa_add.extend(hex_data)
            prefix_version = p.version
        # self.logger.debug(f"spa_add: {spa_add}")
        next_hop = link_meta["remote_ip"]
        ip_version = next_hop.version
        next_hop = [ip_version] + list(next_hop.packed)
        next_hop = [len(next_hop)] + next_hop
        as_path = [self.agent.config["local_as"]]
        self.logger.debug(f"spa_add: {spa_add}")
        data = get_bird_spa_data(spa_add,
                                 spa_del,
                                 link_name,
                                 f"rpdp{prefix_version}",
                                 ip_version,
                                 next_hop,
                                 as_path,
                                 link_meta["as4_session"],
                                 link_meta["is_interior"])
        msg = get_agent_bird_msg(
            data, "dsav", self.name, 0, False)
        self.logger.debug(f"sending spa on {link_name} : {msg}")
        try:
            self.agent.link_man.put_send_async(msg)
            self.agent.link_man.update_link_kv(
                link_name, "initial_broadcast", True)
            self.logger.debug(f"finished sending spa on {link_name}")
        except Exception as e:
            self.logger.error(e)

    def _send_spa_origin_intra(self, link_name, link_meta, prefixes):
        """
        send spa origin msg
        update the link_meta["initial_broadcast"] to True
        the prefixes must either be a ipv4 prefix or a ipv6 prefix
        """
        # send to all neighbors
        # self.logger.debug(
            # f"building spa origin on intra {link_name}:{prefixes}")
        spa_add = []
        spa_del = []  # when broadcasting, we don't delete any prefix
        prefix_version = None
        for p, p_data in prefixes.items():
            # self.logger.debug(f"p: {p}, data: {p_data}")
            spa_add.extend(get_intra_spa_nlri_hex(
                netaddr.IPAddress(self.agent.config["router_id"]),
                p,
                0,  # flag
                p_data["miig_type"],
                p_data["miig_tag"]))
            prefix_version = p.version

        next_hop = link_meta["remote_ip"]
        ip_version = next_hop.version
        next_hop = [ip_version] + list(next_hop.packed)
        next_hop = [len(next_hop)] + next_hop
        as_path = [self.agent.config["local_as"]]
        # self.logger.debug(f"spa_add: {spa_add}")
        try:
            data = get_bird_spa_data(spa_add,
                                    spa_del,
                                    link_name,
                                    f"rpdp{prefix_version}",
                                    ip_version,
                                    next_hop,
                                    as_path,
                                    link_meta["as4_session"],
                                    link_meta["is_interior"])
            msg = get_agent_bird_msg(
                data, "dsav", self.name, 0, False)
        except Exception as e:
            self.logger.exception(e)
            self.logger.error(e)
            return
        # self.logger.debug(f"sending spa on {link_name} : {msg}")
        self.agent.link_man.put_send_async(msg)
        self.logger.debug(f"sent spa on {link_name} : {msg}")
        self.agent.link_man.update_link_kv(
            link_name, "initial_broadcast", True)
        # self.logger.debug(f"key updated {link_name} : {msg}")

    def send_spa_init(self):
        """
        decide whether to send initial broadcast on each link
        """
        rpdp_links = self.agent.link_man.get_all_link_meta()
        local_prefixes = self.agent.bird_man.get_local_fib()
        self.logger.debug(f"raw_local_prefixes: {local_prefixes}")
        for p,p_srcs in local_prefixes.items():
            # TODO: remove filter
            # currently we only send spa for prefixes that in our config
            p_d = {'srcs':p_srcs
                   ,'miig_type':DEFAULT_MIIG_TYPE
                   ,'miig_tag':DEFAULT_MIIG_TAG}
            if p in self.agent.config["prefixes"]:
                p_d["miig_type"] = self.agent.config["prefixes"][p]["miig_type"]
                p_d["miig_tag"] = self.agent.config["prefixes"][p]["miig_tag"]
            local_prefixes[p] = p_d
        # TODO: remove filter
        temp = {}
        for p in local_prefixes:
            if p.version == 6:
                if p.prefixlen > 120:
                    continue
            if p.version == 4:
                if str(p).startswith('1.1'):
                    continue
            temp[p] = local_prefixes[p]
        local_prefixes = temp
        self.logger.debug(f"local_prefixes: {local_prefixes}")
        for link_name, link in rpdp_links.items():
            if link["initial_broadcast"]:
                continue
            if link["is_interior"]:
                self.logger.debug(f"link {link_name} is inter")
                self._send_spa_origin_inter(
                    link_name, link, local_prefixes)
                self.logger.debug(f"finished sending spa on {link_name}")
            else:
                self.logger.debug(f"link {link_name} is intra")
                self._send_spa_origin_intra(
                    link_name, link, local_prefixes)
                self.logger.debug(f"finished sending spa on {link_name}")

        

    def _gen_rules(self,spa_data,spd_data,is_inter):
        """
        generate new sav rules based on spa and spd data
        """
        # self.logger.debug(f"spa_data: {spa_data}")
        # self.logger.debug(f"spd_data: {spd_data}")
        new_rules = {}
        # TODO add logic for different policy, here we use the simplest one
        for router_id, prefixes_data in spa_data.items():
            if not router_id in spd_data:
                self.logger.debug(spd_data)
                self.logger.debug(spa_data)
                self.logger.warning(f"no spd data for {router_id}")
                continue
            this_spd = spd_data[router_id]
            for allowed_link_name in this_spd:
                link_meta = self.agent.link_man.get_by_name(
                    allowed_link_name)
                local_ip = link_meta["local_ip"]
                for prefix, prefix_data in prefixes_data.items():
                    rule = get_sav_rule(
                        prefix, get_ifa_by_ip(local_ip), self.name, router_id, is_inter)
                    rule_key = get_key_from_sav_rule(rule)
                    if rule_key in new_rules:
                        raise KeyError("sav rule key conflict")
                    new_rules[rule_key] = rule
        # self.logger.debug(f"new_rules: {new_rules}")
        return new_rules
        
    def _refresh_sav_rules(self):
        """
        based on current spd and spa data, generate new sav rules
        and update the sav table in agent
        """
        old_rules = self.agent.get_sav_rules_by_app(self.name, None)
        # self.logger.debug(f"old_rules: {old_rules}")
        
        spa_data = self.spa_data["intra"]
        spd_data = self.spd_data["intra"]
        # self.logger.debug(f"spa_data: {spa_data}")
        # self.logger.debug(f"spd_data: {spd_data}")
        new_intra_rules = self._gen_rules(spa_data, spd_data, False)
        spa_data = self.spa_data["inter"]
        spd_data = self.spd_data["inter"]
        self.logger.debug(f"spa_data: {spa_data}")
        self.logger.debug(f"spd_data: {spd_data}")
        new_inter_rules = self._gen_rules(spa_data, spd_data, True)
        new_rules = {**new_intra_rules, **new_inter_rules}
        # self.logger.debug(f"new_rules: {new_rules}")
        add_dict, del_set = rule_dict_diff(old_rules, new_rules)
        # self.logger.debug(add_dict)
        # self.logger.debug(del_set)
        self.agent.update_sav_table_by_app_name(add_dict, del_set, self.name)