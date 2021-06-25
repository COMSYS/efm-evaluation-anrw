#!/usr/bin/python3

import asyncio

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.quic.events import DatagramFrameReceived, QuicEvent

import _thread
import time

import sys


from argparse import ArgumentParser


parser = ArgumentParser(description="QUIC EFM Datagram Server")

parser.add_argument('--serverport', '-s',
                    dest="serverport",
                    action="store",
                    help="QUIC Server port",
                    required=True)

parser.add_argument('--efmvariants',
                    dest="efmvariants",
                    action="store",
                    required=True,
                    help="Which measurement to perform?")
parser.add_argument('--certpath', '-c',
                    dest="certpath",
                    action="store",
                    required=True,
                    help="Which ssl_cert?")
parser.add_argument('--keypath', '-k',
                    dest="keypath",
                    action="store",
                    required=True,
                    help="Which ssl_key?")
parser.add_argument('--packets', '-p',
                    dest="packets",
                    action="store",
                    help="How many packets should be sent?",
                    required=True)



args = parser.parse_args()


class MyConnectionProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.packet_count = 0
        self.started = False

    def quic_event_received(self, event: QuicEvent) -> None:

        if isinstance(event, DatagramFrameReceived):

            thirteenhundred_bytes = 1227 * "a"
            b = bytes(thirteenhundred_bytes, 'utf-8')
            self._quic.send_datagram_frame(b)
            self.transmit()
            self.packet_count += 1
            if self.packet_count % 500 == 0:
                print("Server, Packet Count ", self.packet_count)

            if self.packet_count >= int(args.packets):
                self._quic.send_datagram_frame(b'CLOSECLOSECLOSE')
                self.transmit()
                print(42*"###")
                print(42*"###")
                print("Server Closes the Connection")
                self._quic.close(42, 1234)

        return



if __name__ == "__main__":


    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain(args.certpath,args.keypath)

    configuration.max_datagram_frame_size = 65536


    configuration.efm_variants = args.efmvariants

    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        serve(
            "0.0.0.0",
            args.serverport,
            configuration=configuration,
            create_protocol=MyConnectionProtocol,
        )
    )
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass









    
