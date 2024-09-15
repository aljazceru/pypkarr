#!/usr/bin/env python3

import asyncio
import time
import logging
from argparse import ArgumentParser
from src.client import PkarrClient
from src.public_key import PublicKey
from src.keypair import Keypair
from src.errors import PkarrError
import bencodepy


DEFAULT_MINIMUM_TTL = 300  # 5 minutes
DEFAULT_MAXIMUM_TTL = 24 * 60 * 60  # 24 hours
DEFAULT_BOOTSTRAP_NODES = [
    "router.bittorrent.com:6881",
    "router.utorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "dht.libtorrent.org:25401"
]

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

async def resolve(client: PkarrClient, public_key: PublicKey):
    start_time = time.time()
    try:
        signed_packet = await client.lookup(public_key.to_z32(), max_attempts=200, timeout=60)
        elapsed = time.time() - start_time

        if signed_packet:
            print(f"\nResolved in {int(elapsed * 1000)} milliseconds SignedPacket ({public_key.to_z32()}):")
            print(f"    last_seen: {signed_packet.elapsed()} seconds ago")
            print(f"    timestamp: {signed_packet.timestamp},")
            print(f"    signature: {signed_packet.signature.hex().upper()}")
            print("    records:")
            for rr in signed_packet.packet.answers:
                print(f"        {rr}")
        else:
            print(f"\nFailed to resolve {public_key.to_z32()}")
    except PkarrError as e:
        print(f"Got error: {e}")


async def main():
    parser = ArgumentParser(description="Resolve Pkarr records")
    parser.add_argument("public_key", help="z-base-32 encoded public key")
    parser.add_argument("--bootstrap", nargs='+', default=DEFAULT_BOOTSTRAP_NODES,
                        help="Bootstrap nodes (default: %(default)s)")
    args = parser.parse_args()

    try:
        public_key = PublicKey(args.public_key)
    except PkarrError as e:
        logging.error(f"Invalid public key: {e}")
        return

    keypair = Keypair.random()
    client = PkarrClient(keypair, args.bootstrap)

    logging.info(f"Resolving Pkarr: {args.public_key}")
    logging.info("\n=== COLD LOOKUP ===")
    await resolve(client, public_key)

    await asyncio.sleep(1)

    logging.info("\n=== SUBSEQUENT LOOKUP ===")
    await resolve(client, public_key)

if __name__ == "__main__":
    asyncio.run(main())