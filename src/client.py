import asyncio
import random
from typing import List, Optional, Union
from .signed_packet import SignedPacket
from .keypair import Keypair
from .public_key import PublicKey
from .resource_record import ResourceRecord
from .packet import Packet
from .errors import PkarrError
import logging
import socket
import struct
import hashlib
import bencodepy
import json
import time

logging.basicConfig(level=logging.DEBUG)

class PkarrClient:
    def __init__(self, keypair: Keypair, bootstrap_nodes: List[str]):
        self.keypair = keypair
        self.bootstrap_nodes = bootstrap_nodes
        self.known_nodes = set(bootstrap_nodes)

    async def lookup(self, public_key: str, max_attempts: int = 100, timeout: int = 30) -> Optional[SignedPacket]:
        """Look up records from the DHT."""
        target_key = PublicKey(public_key)
        
        # Check cache first
        cached_packet, expiration_time = self.cache.get(public_key, (None, 0))
        if cached_packet and time.time() < expiration_time:
            logging.debug(f"Have fresh signed_packet in cache. expires_in={int(expiration_time - time.time())}")
            return cached_packet

        nodes_to_query = set(self.bootstrap_nodes)
        queried_nodes = set()
        
        start_time = time.time()
        attempts = 0

        while nodes_to_query and attempts < max_attempts and (time.time() - start_time) < timeout:
            node = nodes_to_query.pop()
            queried_nodes.add(node)
            attempts += 1
            
            logging.info(f"Attempt {attempts}: Querying node {node}")
            
            try:
                result = await self._request_packet(node, target_key)
                if isinstance(result, SignedPacket):
                    logging.info(f"Found result after {attempts} attempts and {time.time() - start_time:.2f} seconds")
                    # Cache the result
                    self.cache[public_key] = (result, time.time() + result.ttl(DEFAULT_MINIMUM_TTL, DEFAULT_MAXIMUM_TTL))
                    return result
                elif result:
                    new_nodes = set(result) - queried_nodes
                    nodes_to_query.update(new_nodes)
                    logging.info(f"Added {len(new_nodes)} new nodes to query. Total known nodes: {len(self.known_nodes)}")
            except PkarrError as e:
                logging.error(f"Error with node {node}: {e}")
        
        logging.info(f"Lookup completed after {attempts} attempts and {time.time() - start_time:.2f} seconds")
        logging.info(f"Queried {len(queried_nodes)} unique nodes")
        
        if attempts >= max_attempts:
            logging.warning("Lookup terminated: maximum attempts reached")
        elif (time.time() - start_time) >= timeout:
            logging.warning("Lookup terminated: timeout reached")
        else:
            logging.warning("Lookup terminated: no more nodes to query")
        
        return None

    async def _request_packet(self, node: str, target_key: PublicKey, record_type: str) -> Optional[Union[SignedPacket, List[str]]]:
        """Request a packet from a node."""
        logging.info(f"Requesting packet from node {node} for key {target_key.to_z32()} and record_type {record_type}")
        
        try:
            # Extract IP and port from the node string
            if '@' in node:
                _, ip_port = node.split('@')
            else:
                ip_port = node
            
            host, port = ip_port.split(':')
            port = int(port)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)  # Set a 5-second timeout

            # Ensure we have a 20-byte node ID
            node_id = hashlib.sha1(self.keypair.public_key.to_bytes()).digest()

            # Ensure we have a 20-byte info_hash
            info_hash = hashlib.sha1(target_key.to_bytes()).digest()

            # Prepare and send the DHT query
            transaction_id = random.randint(0, 65535).to_bytes(2, 'big')
            message = bencodepy.encode({
                't': transaction_id,
                'y': 'q',
                'q': 'get_peers',
                'a': {
                    'id': node_id,
                    'info_hash': info_hash
                }
            })

            logging.debug(f"Sending message to {host}:{port}: {message}")
            sock.sendto(message, (host, port))

            # Wait for the response
            data, addr = sock.recvfrom(1024)
            logging.debug(f"Received raw response from {addr}: {data}")
            
            # Parse the response
            response = bencodepy.decode(data)
            human_readable = self._decode_response(response)
            logging.info(f"Decoded response from {addr}:\n{json.dumps(human_readable, indent=2)}")
            
            if response.get(b'y') == b'e':
                error_code, error_message = response.get(b'e', [None, b''])[0], response.get(b'e', [None, b''])[1].decode('utf-8', errors='ignore')
                logging.error(f"Received error response: Code {error_code}, Message: {error_message}")
                return None
            
            # Check if the response contains the data we need
            if b'r' in response:
                r = response[b'r']
                if b'values' in r:
                    # Process peer values
                    peer_values = r[b'values']
                    logging.info(f"Found {len(peer_values)} peer values")
                    return await self._connect_to_peers(peer_values, target_key, record_type)
                elif b'nodes' in r:
                    # Process nodes for further querying
                    nodes = r[b'nodes']
                    decoded_nodes = self._decode_nodes(nodes)
                    logging.info(f"Found {len(decoded_nodes)} nodes")
                    self._update_known_nodes(decoded_nodes)
                    return decoded_nodes
            
            return None

        except socket.timeout:
            logging.error(f"Timeout while connecting to {host}:{port}")
        except Exception as e:
            logging.error(f"Error requesting packet from {host}:{port}: {e}")
            logging.exception("Exception details:")
        finally:
            sock.close()

        return None

    async def _connect_to_peers(self, peer_values: List[bytes], target_key: PublicKey, record_type: str) -> Optional[SignedPacket]:
        """Connect to peers and try to retrieve the SignedPacket."""
        for peer_value in peer_values:
            try:
                ip = socket.inet_ntoa(peer_value[:4])
                port = struct.unpack("!H", peer_value[4:])[0]
                peer = f"{ip}:{port}"
                
                logging.info(f"Connecting to peer {peer}")
                
                # Here you would implement the logic to connect to the peer and retrieve the SignedPacket
                # For now, we'll just return a dummy SignedPacket
                return SignedPacket(target_key, b"dummy_signature", Packet())
            
            except Exception as e:
                logging.error(f"Error connecting to peer {peer}: {e}")
        
        return None


    def _decode_response(self, response: dict[bytes, any]) -> dict[str, any]:
        """Decode the bencoded response into a human-readable format."""
        decoded = {}
        for key, value in response.items():
            str_key = key.decode('utf-8')
            if isinstance(value, bytes):
                try:
                    decoded[str_key] = value.decode('utf-8')
                except UnicodeDecodeError:
                    decoded[str_key] = value.hex()
            elif isinstance(value, dict):
                decoded[str_key] = self._decode_response(value)
            elif isinstance(value, list):
                decoded[str_key] = [self._decode_response(item) if isinstance(item, dict) else item.hex() if isinstance(item, bytes) else item for item in value]
            else:
                decoded[str_key] = value

        if 'r' in decoded and 'nodes' in decoded['r']:
            decoded['r']['decoded_nodes'] = self._decode_nodes(response[b'r'][b'nodes'])

        return decoded

    def _decode_nodes(self, nodes_data: bytes) -> List[str]:
        """Decode the compact node info."""
        nodes = []
        for i in range(0, len(nodes_data), 26):
            node_id = nodes_data[i:i+20].hex()
            ip = socket.inet_ntoa(nodes_data[i+20:i+24])
            port = struct.unpack("!H", nodes_data[i+24:i+26])[0]
            nodes.append(f"{ip}:{port}")
        return nodes

    def _update_known_nodes(self, new_nodes: List[str]) -> None:
        """Update the list of known nodes."""
        self.known_nodes.update(new_nodes)
        logging.info(f"Updated known nodes. Total known nodes: {len(self.known_nodes)}")

    async def _send_packet(self, node: str, signed_packet: SignedPacket) -> None:
        """Send a signed packet to a node."""
        # Implement UDP packet sending logic here
        pass

    async def maintain_network(self) -> None:
        """Periodically maintain the network by pinging known nodes and discovering new ones."""
        while True:
            # Implement node discovery and maintenance logic here
            await asyncio.sleep(60)  # Run maintenance every 60 seconds