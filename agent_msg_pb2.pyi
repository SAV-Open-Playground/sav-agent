from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class AgentMsg(_message.Message):
    __slots__ = ["json_str", "sender_id"]
    JSON_STR_FIELD_NUMBER: _ClassVar[int]
    SENDER_ID_FIELD_NUMBER: _ClassVar[int]
    json_str: str
    sender_id: str
    def __init__(self, sender_id: _Optional[str] = ..., json_str: _Optional[str] = ...) -> None: ...
