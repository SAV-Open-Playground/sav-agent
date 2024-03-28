import asyncio
import time
from email.utils import formatdate
from typing import Callable,  Dict, List, Optional
import json
import requests
from common import get_logger
import aioquic
import wsproto
import wsproto.events
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent
from aioquic.tls import SessionTicket
import os

from starlette.applications import Starlette
from starlette.routing import WebSocketRoute
from starlette.templating import Jinja2Templates
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocketDisconnect
AsgiApplication = Callable
HttpConnection = H3Connection
logger = get_logger("quic_server")

SERVER_NAME = "aioquic/" + aioquic.__version__


ROOT = os.path.dirname(__file__)
# STATIC_ROOT = os.environ.get("STATIC_ROOT", os.path.join(ROOT, "htdocs"))
STATIC_URL = "/"
# LOGS_PATH = os.path.join(STATIC_ROOT, "logs")

templates = Jinja2Templates(directory=os.path.join(ROOT, "templates"))


async def ws(websocket):
    """
    WebSocket echo endpoint.
    """
    if "chat" in websocket.scope["subprotocols"]:
        subprotocol = "chat"
    else:
        subprotocol = None
    await websocket.accept(subprotocol=subprotocol)
    try:
        while True:
            message = await websocket.receive_text()
            await websocket.send_text(message)
    except WebSocketDisconnect:
        pass


starlette = Starlette(
    routes=[
        WebSocketRoute("/savop_quic", ws),
    ]
)


async def sav_agent_quic_server(scope: Scope, receive: Receive, send: Send) -> None:

    await starlette(scope, receive, send)


class WebSocketHandler:
    def __init__(
        self,
        *,
        connection: HttpConnection,
        scope: Dict,
        stream_id: int,
        transmit: Callable[[], None],
    ) -> None:
        self.closed = False
        self.connection = connection
        self.queue: asyncio.Queue[Dict] = asyncio.Queue()
        self.scope = scope
        self.stream_id = stream_id
        self.transmit = transmit
        self.websocket: Optional[wsproto.Connection] = None

    def http_event_received(self, event: H3Event) -> None:
        if (isinstance(event, DataReceived)) and (not self.closed):
            if self.websocket is not None:
                self.websocket.receive_data(event.data)
                for ws_event in self.websocket.events():
                    self.websocket_event_received(ws_event)

    def websocket_event_received(self, event: wsproto.events.Event) -> None:
        if isinstance(event, wsproto.events.TextMessage):
            self.queue.put_nowait(
                {"type": "websocket.receive", "text": event.data})

    async def run_asgi(self, app: AsgiApplication) -> None:
        self.queue.put_nowait({"type": "websocket.connect"})
        try:
            await app(self.scope, self.receive, self.send)
        finally:
            if not self.closed:
                await self.send({"type": "websocket.close", "code": 1000})

    async def receive(self) -> Dict:
        return await self.queue.get()

    async def send(self, message: Dict) -> None:
        data = b""
        print(message)
        end_stream = False
        if message["type"] == "websocket.accept":
            subprotocol = message.get("subprotocol")

            self.websocket = wsproto.Connection(wsproto.ConnectionType.SERVER)

            headers = [
                (b":status", b"200"),
                (b"server", SERVER_NAME.encode()),
                (b"date", formatdate(time.time(), usegmt=True).encode()),
            ]
            if subprotocol is not None:
                headers.append(
                    (b"sec-websocket-protocol", subprotocol.encode()))
            self.connection.send_headers(
                stream_id=self.stream_id, headers=headers)

            # consume backlog

        elif message["type"] == "websocket.close":
            if self.websocket is not None:
                data = self.websocket.send(
                    wsproto.events.CloseConnection(code=message["code"])
                )
            else:
                self.connection.send_headers(
                    stream_id=self.stream_id, headers=[(b":status", b"403")]
                )
            end_stream = True
        elif message["type"] == "websocket.send":
            text_msg = message.get("text")
            print(text_msg)
            if text_msg is not None:
                try:
                    requests.post('http://localhost:8888/savop_quic',
                                  json=json.loads(text_msg), timeout=30)
                except Exception as e:
                    logger.error(e)
                data = self.websocket.send(
                    wsproto.events.TextMessage(data="good")
                )

        if data:
            self.connection.send_data(
                stream_id=self.stream_id, data=data, end_stream=end_stream
            )
        if end_stream:
            self.closed = True
        self.transmit()


Handler = WebSocketHandler


class HttpServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._handlers: Dict[int, Handler] = {}
        self._http: Optional[HttpConnection] = None

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived) and event.stream_id not in self._handlers:
            authority = None
            headers = []
            http_version = "3"
            raw_path = b""
            method = ""
            protocol = None
            for header, value in event.headers:
                if header == b":authority":
                    authority = value
                    headers.append((b"host", value))
                elif header == b":method":
                    method = value.decode()
                elif header == b":path":
                    raw_path = value
                elif header == b":protocol":
                    protocol = value.decode()
                elif header and not header.startswith(b":"):
                    headers.append((header, value))
            if b"?" in raw_path:
                path_bytes, query_string = raw_path.split(b"?", maxsplit=1)
            else:
                path_bytes, query_string = raw_path, b""
            path = path_bytes.decode()

            # FIXME: add a public API to retrieve peer address
            client_addr = self._http._quic._network_paths[0].addr
            client = (client_addr[0], client_addr[1])

            handler: Handler
            scope: Dict
            if method == "CONNECT" and protocol == "websocket":
                subprotocols: List[str] = []
                for header, value in event.headers:
                    if header == b"sec-websocket-protocol":
                        subprotocols = [x.strip()
                                        for x in value.decode().split(",")]
                scope = {
                    "client": client,
                    "headers": headers,
                    "http_version": http_version,
                    "method": method,
                    "path": path,
                    "query_string": query_string,
                    "raw_path": raw_path,
                    "root_path": "",
                    "scheme": "wss",
                    "subprotocols": subprotocols,
                    "type": "websocket",
                }
                handler = WebSocketHandler(
                    connection=self._http,
                    scope=scope,
                    stream_id=event.stream_id,
                    transmit=self.transmit,
                )
            else:
                print("error")
            self._handlers[event.stream_id] = handler
            asyncio.ensure_future(handler.run_asgi(sav_agent_quic_server))

        elif (

            isinstance(event, (DataReceived, HeadersReceived))
            and event.stream_id in self._handlers
        ):
            handler = self._handlers[event.stream_id]
            handler.http_event_received(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        # print(event)
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self._http = H3Connection(self._quic, enable_webtransport=True)
        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)


class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


async def main(
    host: str,
    port: int,
    configuration: QuicConfiguration,
    retry: bool,
) -> None:
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=HttpServerProtocol,
        retry=retry,
    )
    await asyncio.Future()


if __name__ == "__main__":

    # load SSL certificate and key
    log = r'./server_cert.log'
    with open(log, 'w'):
        pass
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
        quic_logger=None,
        secrets_log_file=open(log, 'a'),
    )
    # configuration.load_cert_chain(r'/root/savop/cert.pem',
    #                               r'/root/savop/key.pem')
    # configuration.load_cert_chain(r'/root/savop-dev/savop/rpki/nodes/node_65501/cert.pem',
    #   r'/root/savop-dev/savop/rpki/nodes/node_65501/key.pem')
    print("Starting server on [::]:7777")
    asyncio.run(main(
        host='::',
        port=7777,
        configuration=configuration,
        retry=False,
    ))
