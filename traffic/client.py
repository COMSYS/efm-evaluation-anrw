#!/usr/bin/python3

import sys
import asyncio
import ssl
from typing import Optional, cast

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.quic.events import QuicEvent, ConnectionTerminated

import time

from argparse import ArgumentParser

parser = ArgumentParser(description="QUIC EFM Datagram Client")
parser.add_argument('--target', '-t',
                    dest="target",
                    action="store",
                    help="Target IP address",
                    required=True)

parser.add_argument('--srcport', '-s',
                    dest="srcport",
                    action="store",
                    help="QUIC SRC port",
                    required=True)

parser.add_argument('--dstport', '-z',
                    dest="dstport",
                    action="store",
                    help="QUIC DST port",
                    required=True)                    

parser.add_argument('--efmvariants',
                    dest="efmvariants",
                    action="store",
                    required=True,
                    help="Which measurement to perform?")

parser.add_argument('--duration', '-d',
                    dest="duration",
                    action="store",
                    help="How long should traffic be generated?",
                    required=False)

parser.add_argument('--packets', '-p',
                    dest="packets",
                    action="store",
                    help="How many packets should be sent?",
                    required=True)

args = parser.parse_args()



class MyConnectionProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.done = False
        self.packet_count = 0
        self.watchdog = time.perf_counter()

    def quic_event_received(self, event: QuicEvent) -> None:

        if isinstance(event, ConnectionTerminated):
            self.done = True

        self.watchdog = time.perf_counter()
                
            
        return

    async def sendDatagram(self):
        thirteenhundred_bytes = 1227 * "a"
        b = bytes(thirteenhundred_bytes, 'utf-8')
        self._quic.send_datagram_frame(b)
        self.transmit()

    async def run_trash_traffic(self):

        while not self.done:
            await self.sendDatagram()
            await asyncio.sleep(0.0012)
            self.packet_count += 1
            if self.packet_count % 500 == 0:
                print("Client, Packet Count ", self.packet_count)

            """
            Check if there has not been a response from the server for quite some time as it just might be the case that the connection close got dropped.            
            """
            if time.perf_counter() - self.watchdog > 60:
                print("No reponse from the server for 60 seconds. Close the client, too.")
                self.done = True

    async def traffic_timer(self):
        print("Start timer: {}".format(str(args.duration)))
        await asyncio.sleep(int(args.duration))
        print("Timer finished")
        self.done = True



async def main():


    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.max_datagram_frame_size = 65536

    configuration.efm_variants = args.efmvariants

    async with connect(args.target, args.dstport, configuration=configuration, create_protocol=MyConnectionProtocol, local_port=int(args.srcport)) as client:
        client = cast(MyConnectionProtocol, client)

        loop = asyncio.get_event_loop()

        trash_traffic = loop.create_task(client.run_trash_traffic())

        await trash_traffic


loop = asyncio.get_event_loop()
result = loop.run_until_complete(main())

print("Done")
