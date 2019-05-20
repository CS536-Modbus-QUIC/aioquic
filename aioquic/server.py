import asyncio
import os
from typing import Any, Callable, Dict, Optional, Text, TextIO, Union, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .connection import NetworkAddress, QuicConnection, QuicStreamHandler
from .packet import (
    PACKET_TYPE_INITIAL,
    encode_quic_retry,
    encode_quic_version_negotiation,
    pull_quic_header,
)
from .tls import Buffer

__all__ = ["serve"]

QuicConnectionHandler = Callable[[QuicConnection], None]


class QuicServer(asyncio.DatagramProtocol):
    def __init__(
        self,
        *,
        certificate: Any,
        private_key: Any,
        connection_handler: Optional[QuicConnectionHandler] = None,
        stream_handler: Optional[QuicStreamHandler] = None,
        stateless_retry: bool = False,
        secrets_log_file: Optional[TextIO] = None,
    ) -> None:
        self._certificate = certificate
        self._connections: Dict[bytes, QuicConnection] = {}
        self._private_key = private_key
        self._secrets_log_file = secrets_log_file
        self._transport: Optional[asyncio.DatagramTransport] = None

        if connection_handler is not None:
            self._connection_handler = connection_handler
        else:
            self._connection_handler = lambda c: None

        self._stream_handler = stream_handler

        if stateless_retry:
            self._retry_key = rsa.generate_private_key(
                public_exponent=65537, key_size=512, backend=default_backend()
            )
        else:
            self._retry_key = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: Union[bytes, Text], addr: NetworkAddress) -> None:
        data = cast(bytes, data)
        buf = Buffer(data=data)
        header = pull_quic_header(buf, host_cid_length=8)

        # version negotiation
        if (
            header.version is not None
            and header.version not in QuicConnection.supported_versions
        ):
            self._transport.sendto(
                encode_quic_version_negotiation(
                    source_cid=header.destination_cid,
                    destination_cid=header.source_cid,
                    supported_versions=QuicConnection.supported_versions,
                ),
                addr,
            )
            return

        connection = self._connections.get(header.destination_cid, None)
        if connection is None and header.packet_type == PACKET_TYPE_INITIAL:
            # stateless retry
            if self._retry_key is not None:
                retry_message = str(addr).encode("ascii")
                if not header.token:
                    retry_token = self._retry_key.sign(
                        retry_message,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                    self._transport.sendto(
                        encode_quic_retry(
                            version=header.version,
                            source_cid=os.urandom(8),
                            destination_cid=header.source_cid,
                            original_destination_cid=header.destination_cid,
                            retry_token=retry_token,
                        ),
                        addr,
                    )
                    return
                else:
                    try:
                        self._retry_key.public_key().verify(
                            header.token,
                            retry_message,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH,
                            ),
                            hashes.SHA256(),
                        )
                    except InvalidSignature:
                        return

            # create new connection
            connection = QuicConnection(
                certificate=self._certificate,
                private_key=self._private_key,
                is_client=False,
                secrets_log_file=self._secrets_log_file,
                stream_handler=self._stream_handler,
            )
            connection.connection_made(self._transport)
            self._connections[connection.host_cid] = connection
            self._connection_handler(connection)

        if connection is not None:
            connection.datagram_received(data, addr)


async def serve(
    host: str,
    port: int,
    *,
    certificate: Any,
    private_key: Any,
    connection_handler: QuicConnectionHandler = None,
    stream_handler: QuicStreamHandler = None,
    secrets_log_file: Optional[TextIO] = None,
    stateless_retry: bool = False,
) -> None:
    """
    Start a QUIC server at the given `host` and `port`.

    :func:`serve` requires a TLS certificate and private key, which can be
    specified using the following arguments:

    * ``certificate`` is the server's TLS certificate.
      See :func:`cryptography.x509.load_pem_x509_certificate`.
    * ``private_key`` is the server's private key.
      See :func:`cryptography.hazmat.primitives.serialization.load_pem_private_key`.

    :func:`serve` also accepts the following optional arguments:

    * ``connection_handler`` is a callback which is invoked whenever a
      connection is created. It must be a a function accepting a single
      argument: a :class:`~aioquic.QuicConnection`.
    * ``secrets_log_file`` is  a file-like object in which to log traffic
      secrets. This is useful to analyze traffic captures with Wireshark.
    * ``stateless_retry`` specifies whether a stateless retry should be
      performed prior to handling new connections.
    * ``stream_handler`` is a callback which is invoked whenever a stream is
      created. It must accept two arguments: a :class:`asyncio.StreamReader`
      and a :class:`asyncio.StreamWriter`.
    """

    loop = asyncio.get_event_loop()

    _, protocol = await loop.create_datagram_endpoint(
        lambda: QuicServer(
            certificate=certificate,
            connection_handler=connection_handler,
            private_key=private_key,
            secrets_log_file=secrets_log_file,
            stream_handler=stream_handler,
            stateless_retry=stateless_retry,
        ),
        local_addr=(host, port),
    )