import argparse
import asyncio
import logging
import pickle
import ssl
from typing import Optional, cast

#from dnslib.dns import QTYPE, DNSQuestion, DNSRecord
from quic_logger import QuicDirectoryLogger

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

from pymodbus.client.common import ModbusClientMixin
from pymodbus.framer.socket_framer import ModbusSocketFramer
from pymodbus.factory import ClientDecoder
from pymodbus.transaction import DictTransactionManager
logger = logging.getLogger("client")
logger.setLevel('DEBUG')


class ModbusUdpClientProtocol(ModbusClientMixin):
    def __init__(self, client):
        self.client = client
        self.decoder = ClientDecoder()
        self.framer = ModbusSocketFramer(self.decoder, client=self)
        self._ack_waiter: Optional[asyncio.Future[None]] = None
        self.transaction = DictTransactionManager(self)
        # self.broadcast_enable

    # BaseModbusAsyncClientProtocol::execute
    async def execute(self, request=None):
        req = self._execute(request)
        resp = await asyncio.wait_for(req, timeout=2)
        return resp

    # BaseModbusAsyncClientProtocol::_execute
    def _execute(self, request, **kwargs):
        # Build Framer Packet
        request.transaction_id = self.transaction.getNextTID()
        packet = self.framer.buildPacket(message=request)
        logger.debug(b"send: " + packet)

        # Send packet through QUIC
        self.send(packet)

        # Get response
        waiter = self.client._loop.create_future()
        self._ack_waiter = waiter
        self.client.transmit()
        return waiter

    def send(self, data):
        self.client.send(data)

    def dataReceived(self, data):
        logger.debug(b"recv: " + data)
        unit = self.framer.decode_data(data=data).get("unit", 0)
        self.framer.processIncomingPacket(data, self._handleResponse, unit=unit)

        waiter = self._ack_waiter
        self._ack_waiter = None
        waiter.set_result(None)

    def _handleResponse(self, reply, **kwargs):
        if reply is not None:
            tid = reply.transaction_id
            handler = self.transaction.getTransaction(tid)
            if handler:
                self.resolve_future(handler, reply)
            else:
                logger.debug("Unrequested message: " + str(reply))


class ModbusClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.protocol = ModbusUdpClientProtocol(client=self)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self.protocol._ack_waiter is not None:
            if isinstance(event, StreamDataReceived):
                data = event.data
                logger.info("receive data" + str(data))
                self.protocol.dataReceived(data)


    def send(self, data):
        stream_id = self._quic.get_next_available_stream_id()
        logger.debug(f"Stream ID: {stream_id}")
        end_stream = False
        self._quic.send_stream_data(stream_id, data, end_stream)

UNIT = 0x01
async def start_async_test(client):
    # ----------------------------------------------------------------------- #
    # specify slave to query
    # ----------------------------------------------------------------------- #
    # The slave to query is specified in an optional parameter for each
    # individual request. This can be done by specifying the `unit` parameter
    # which defaults to `0x00`
    # ----------------------------------------------------------------------- #
    logger.debug("Reading Coils")
    rr = await client.read_coils(1, 1, unit=0x01)

    # ----------------------------------------------------------------------- #
    # example requests
    # ----------------------------------------------------------------------- #
    # simply call the methods that you would like to use. An example session
    # is displayed below along with some assert checks. Note that some modbus
    # implementations differentiate holding/input discrete/coils and as such
    # you will not be able to write to these, therefore the starting values
    # are not known to these tests. Furthermore, some use the same memory
    # blocks for the two sets, so a change to one is a change to the other.
    # Keep both of these cases in mind when testing as the following will
    # _only_ pass with the supplied asynchronous modbus server (script supplied).
    # ----------------------------------------------------------------------- #
    logger.debug("Write to a Coil and read back")
    rq = await client.write_coil(0, True, unit=UNIT)
    rr = await client.read_coils(0, 1, unit=UNIT)
    #assert (rq.function_code < 0x80)  # test that we are not an error
    #assert (rr.bits[0] == True)  # test the expected value

    logger.debug("Write to multiple coils and read back- test 1")
    rq = await client.write_coils(1, [True] * 8, unit=UNIT)
    #assert (rq.function_code < 0x80)  # test that we are not an error
    rr = await client.read_coils(1, 21, unit=UNIT)
    #assert (rr.function_code < 0x80)  # test that we are not an error
    resp = [True] * 21

    # If the returned output quantity is not a multiple of eight,
    # the remaining bits in the final data byte will be padded with zeros
    # (toward the high order end of the byte).

    resp.extend([False] * 3)
    #assert (rr.bits == resp)  # test the expected value

    logger.debug("Write to multiple coils and read back - test 2")
    rq = await client.write_coils(1, [False] * 8, unit=UNIT)
    rr = await client.read_coils(1, 8, unit=UNIT)
    #assert (rq.function_code < 0x80)  # test that we are not an error
    #assert (rr.bits == [False] * 8)  # test the expected value

    logger.debug("Read discrete inputs")
    rr = await client.read_discrete_inputs(0, 8, unit=UNIT)
   # assert (rq.function_code < 0x80)  # test that we are not an error

    logger.debug("Write to a holding register and read back")
    rq = await client.write_register(1, 10, unit=UNIT)
    rr = await client.read_holding_registers(1, 1, unit=UNIT)
   # assert (rq.function_code < 0x80)  # test that we are not an error
    #assert (rr.registers[0] == 10)  # test the expected value

    logger.debug("Write to multiple holding registers and read back")
    rq = await client.write_registers(1, [10] * 8, unit=UNIT)
    rr = await client.read_holding_registers(1, 8, unit=UNIT)
    #assert (rq.function_code < 0x80)  # test that we are not an error
    #assert (rr.registers == [10] * 8)  # test the expected value

    logger.debug("Read input registers")
    rr = await client.read_input_registers(1, 8, unit=UNIT)
    #assert (rq.function_code < 0x80)  # test that we are not an error

    arguments = {
        'read_address': 1,
        'read_count': 8,
        'write_address': 1,
        'write_registers': [20] * 8,
    }
    logger.debug("Read write registeres simulataneously")
    rq = await client.readwrite_registers(unit=UNIT, **arguments)
    rr = await client.read_holding_registers(1, 8, unit=UNIT)
    #assert (rq.function_code < 0x80)  # test that we are not an error
    #assert (rq.registers == [20] * 8)  # test the expected value
    #assert (rr.registers == [20] * 8)  # test the expected value
    await asyncio.sleep(1)

def save_session_ticket(ticket):
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


async def run(
    configuration: QuicConfiguration,
    host: str,
    port: int,
) -> None:
    logger.debug(f"Connecting to {host}:{port}")
    async with connect(
        host,
        port,
        configuration=configuration,
        session_ticket_handler=save_session_ticket,
        create_protocol=ModbusClient,
    ) as client:
        client = cast(ModbusClient, client)
        logger.debug("Sending Modbus query")
        await start_async_test(client.protocol)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modbus over QUIC client")
    parser.add_argument("-t", "--type", type=str, help="Type of record to ")
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="The remote peer's host name or IP address",
    )
    parser.add_argument(
        "--port", type=int, default=4784, help="The remote peer's port number"
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )

    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    configuration = QuicConfiguration(
        alpn_protocols=["modbus"], is_client=True, max_datagram_frame_size=65536
    )
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.quic_log:
        configuration.quic_logger = QuicDirectoryLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            logger.debug(f"Unable to read {args.session_ticket}")
            pass
    else:
        logger.debug("No session ticket defined...")

    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        run(
            configuration=configuration,
            host=args.host,
            port=args.port,
        )
    )