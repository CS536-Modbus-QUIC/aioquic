import argparse
import asyncio
import logging
import traceback
from binascii import b2a_hex

from typing import Dict, Optional

from pymodbus.constants import Defaults
# import pymodbus.constants
from pymodbus.datastore import ModbusServerContext
from pymodbus.device import ModbusControlBlock, ModbusDeviceIdentification
from pymodbus.exceptions import NoSuchSlaveException
from pymodbus.factory import ServerDecoder
from pymodbus.framer.socket_framer import ModbusSocketFramer
from pymodbus.utilities import hexlify_packets
from pymodbus.pdu import ModbusExceptions as merror
from quic_logger import QuicDirectoryLogger

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ProtocolNegotiated, QuicEvent, StreamDataReceived
from aioquic.tls import SessionTicket

_logger = logging.getLogger(__name__)
try:
    import uvloop
except ImportError:
    uvloop = None

class ModbusProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context = ModbusServerContext()
        self.broadcast_enable = False
        self.decoder = ServerDecoder()
        self.framer = ModbusSocketFramer(self.decoder)
        self.response_manipulator = None

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            self.handle(event)

    def handle(self, event):
        reset_frame = False
        try:
            units = self.context.slaves()
            if isinstance(event, QuicEvent):
                # addr is populated when talking over UDP
                data = event.data
            else:
                print("event is none")
                return

            if not isinstance(units, (list, tuple)):
                units = [units]
            # if broadcast is enabled make sure to
            # process requests to address 0
            if self.broadcast_enable:  # pragma: no cover
                if 0 not in units:
                    units.append(0)

            if _logger.isEnabledFor(logging.DEBUG):
                _logger.debug('Handling data: ' + hexlify_packets(data))

            single = self.context.single
            self.framer.processIncomingPacket(
                data=data, callback=lambda x: self.execute(x, event),
                unit=units, single=single)
        finally:
            if reset_frame:
                self.framer.resetFrame()
                reset_frame = False

    def execute(self, request, event: QuicEvent):
        """ The callback to call with the resulting message

        :param request: The decoded request message
        """
        broadcast = False
        try:
            if self.broadcast_enable and request.unit_id == 0:
                broadcast = True
                # if broadcasting then execute on all slave contexts,
                # note response will be ignored
                for unit_id in self.context.slaves():
                    response = request.execute(self.context[unit_id])
            else:
                context = self.context[request.unit_id]
                response = request.execute(context)
        except NoSuchSlaveException as ex:
            _logger.error("requested slave does "
                          "not exist: %s" % request.unit_id)
            if self.ignore_missing_slaves:
                return  # the client will simply timeout waiting for a response
            response = request.doException(merror.GatewayNoResponse)
        except Exception as ex:
            _logger.error("Datastore unable to fulfill request: "
                          "%s; %s", ex, traceback.format_exc())
            response = request.doException(merror.SlaveFailure)
        # no response when broadcasting
        if not broadcast:
            response.transaction_id = request.transaction_id
            response.unit_id = request.unit_id
            skip_encoding = False
            if self.response_manipulator:
                response, skip_encoding = self.response_manipulator(response)
            self.send(response, event, skip_encoding=skip_encoding)

    def send(self, message, event: QuicEvent, **kwargs):
        def __send(msg, *addr):
            if _logger.isEnabledFor(logging.DEBUG):
                _logger.debug('send: [%s]- %s' % (message, b2a_hex(msg)))
            self._quic.send_stream_data(event.stream_id, msg, False)

        skip_encoding = kwargs.get("skip_encoding", False)
        if skip_encoding:
            __send(message, event)
        elif message.should_respond:
            # self.server.control.Counter.BusMessage += 1
            pdu = self.framer.buildPacket(message)
            __send(pdu, event)
        else:
            _logger.debug("Skipping sending response!!")


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


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Modbus over QUIC server")
    parser.add_argument(
        "--host",
        type=str,
        default="::",
        help="listen on the specified address (defaults to ::)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4784,
        help="listen on the specified port (defaults to 4784)",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=str,
        help="load the TLS private key from the specified file",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        required=True,
        help="load the TLS certificate from the specified file",
    )
    parser.add_argument(
        "--resolver",
        type=str,
        default="8.8.8.8",
        help="Upstream Classic DNS resolver to use",
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="send a retry for new connections",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if args.quic_log:
        quic_logger = QuicDirectoryLogger(args.quic_log)
    else:
        quic_logger = None

    configuration = QuicConfiguration(
        alpn_protocols=["modbus"],
        is_client=False,
        max_datagram_frame_size=65536,
        quic_logger=quic_logger,
    )

    configuration.load_cert_chain(args.certificate, args.private_key)

    ticket_store = SessionTicketStore()

    if uvloop is not None:
        uvloop.install()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        serve(
            args.host,
            args.port,
            configuration=configuration,
            create_protocol=ModbusProtocol,
            session_ticket_fetcher=ticket_store.pop,
            session_ticket_handler=ticket_store.add,
            retry=args.retry,
        )
    )
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass