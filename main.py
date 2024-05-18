import socket
import struct
import time
import hashlib
import requests
import datetime


def create_version_message():
    version = 70015
    services = 0
    timestamp = int(time.time())
    addr_recv_services = services
    addr_recv_ip = socket.inet_aton('127.0.0.1')
    addr_recv_port = 8333
    addr_trans_services = services
    addr_trans_ip = socket.inet_aton('127.0.0.1')
    addr_trans_port = 8333
    nonce = 0
    user_agent_bytes = 0
    start_height = 0
    relay = 0

    addr_recv = struct.pack('<Q16sH', addr_recv_services,
                            addr_recv_ip + b'\x00' * 10, addr_recv_port)
    addr_trans = struct.pack(
        '<Q16sH', addr_trans_services, addr_trans_ip + b'\x00' * 10, addr_trans_port)

    payload = struct.pack('<LQQ26s26sQbL?', version, services, timestamp,
                          addr_recv, addr_trans, nonce, user_agent_bytes, start_height, relay)

    magic = struct.pack('<L', 0xD9B4BEF9)
    command = b'version' + b'\x00' * 5
    length = struct.pack('<L', len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    message = magic + command + length + checksum + payload
    return message


def connect_to_node():
    node_ip = 'seed.bitcoin.sipa.be'
    port = 8333

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((node_ip, port))

    version_message = create_version_message()
    s.send(version_message)

    return s


def recv_message(s):
    response = s.recv(1024)
    return response


def send_verack(s):
    magic = struct.pack('<L', 0xD9B4BEF9)
    command = b'verack' + b'\x00' * 6
    payload = b''
    length = struct.pack('<L', len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    verack_message = magic + command + length + checksum + payload
    s.send(verack_message)
    print("Verack Message sent")


def parse_header(data):
    try:
        magic, command, length, checksum = struct.unpack('<L12sL4s', data[:24])
        command = command.split(b'\x00', 1)[0].decode('ascii')
        return {
            'magic': magic,
            'command': command,
            'length': length,
            'checksum': checksum,
            'payload': data[24:24 + length]
        }
    except Exception as e:
        print(f"Failed to parse header: {e}")
        return None


def parse_version_payload(payload):
    try:
        version, services, timestamp = struct.unpack('<LQq', payload[:20])
        addr_recv = payload[20:46]
        addr_trans = payload[46:72]
        nonce, = struct.unpack('<Q', payload[72:80])
        user_agent_bytes = payload[80]
        user_agent_start = 81
        user_agent_end = user_agent_start + user_agent_bytes

        if user_agent_end > len(payload):
            raise ValueError("Invalid user agent length")

        user_agent = payload[user_agent_start:user_agent_end].decode('ascii')
        remaining_payload = payload[user_agent_end:]

        if len(remaining_payload) < 5:
            raise ValueError("Insufficient bytes for start_height and relay")

        start_height, relay = struct.unpack('<Lb', remaining_payload[:5])

        return {
            'version': version,
            'services': services,
            'timestamp': timestamp,
            'addr_recv': addr_recv,
            'addr_trans': addr_trans,
            'nonce': nonce,
            'user_agent': user_agent,
            'start_height': start_height,
            'relay': relay
        }
    except struct.error as e:
        print(f"Struct error: {e}")
    except ValueError as e:
        print(f"Value error: {e}")
    return None


def parse_addr(addr):
    services, ip, port = struct.unpack('<Q16sH', addr)
    ip = socket.inet_ntoa(ip[:4])
    return {
        'services': services,
        'ip': ip,
        'port': port
    }


# Connect to the node and send the version message
socket_connection = connect_to_node()

# Receive the message from the node
response = recv_message(socket_connection)

# Split the response to handle multiple messages
version_msg = response[:126]
verack_msg = response[126:]

# Parse the version message
version_header = parse_header(version_msg)
if version_header:
    version_payload = parse_version_payload(version_header['payload'])
    if version_payload:
        addr_recv = parse_addr(version_payload['addr_recv'])
        addr_trans = parse_addr(version_payload['addr_trans'])

        # Print parsed information
        print("Version Message Header:", version_header)
        print("Version Message Payload:", version_payload)
        print("Address Received:", addr_recv)
        print("Address Transmitted:", addr_trans)
    else:
        print("Failed to parse the version payload")

# Parse the verack message
verack_header = parse_header(verack_msg)
if verack_header:
    print("Verack Message Header:", verack_header)
else:
    print("Failed to parse the verack message header")


def send_version_payload(s):
    # Subscribe to events by sending a message to the node indicating interest in inv payloads
    version_message = create_version_message()
    s.send(version_message)


def handle_inv_payload(payload, s):
    # Extract inventory vectors from the inv payload
    # Request detailed information for each inventory vector using getdata payload
    num_inventory = struct.unpack('<B', payload[4:5])[0]
    inventory_list = []
    for i in range(num_inventory):
        inventory_vector = payload[5 + i * 36: 5 + (i + 1) * 36]
        inventory_list.append(inventory_vector)
    request_detailed_info(s, inventory_list)


def request_detailed_info(s, inventory_vectors):
    # Construct and send getdata payload to request detailed information
    payload = b''
    for inventory_vector in inventory_vectors:
        payload += struct.pack('<L', 1)  # Requesting a block
        payload += inventory_vector[4:]  # Hash of the block
    command = b'getdata' + b'\x00' * 5
    length = struct.pack('<L', len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    getdata_message = create_message(command, length, checksum, payload)
    s.send(getdata_message)


def create_message(command, length, checksum, payload):
    return command + length + checksum + payload


def listen_for_events(s):
    while True:
        # Continuously listen for incoming events (inv payloads)
        message = recv_message(s)
        if message:
            print("")
            print("Received message...")
            message_header = parse_header(message)
            print("Message Header")
            print("-----------------")
            print(message_header)
            if message_header['command'] == 'inv':
                handle_inv_payload(message, s)
                block_hash = extract_block_hash_from_inv(message)
                get_block_info(block_hash)
            else:
                print("Unhandled message type")


def parse_inv_message(message):
    try:
        # Parse the message components
        magic = message[:4]
        command = message[4:16].strip(b'\x00').decode('utf-8')

        # Check if the command is "inv"
        if command != "inv":
            return None
        # Parse the message components
        magic = message[:4]
        command = message[4:16].strip(b'\x00').decode('utf-8')
        payload_length = struct.unpack('<L', message[16:20])[0]
        checksum = message[20:24]
        payload = message[24:]

        # Verify the message integrity using the checksum
        calculated_checksum = hashlib.sha256(
            hashlib.sha256(payload).digest()).digest()[:4]
        if checksum != calculated_checksum:
            raise ValueError("Checksum verification failed")

        # Parse the payload to extract inventory vectors
        inventory_vectors = []
        while payload:
            vector_type = struct.unpack('<I', payload[:4])[0]
            hash_bytes = payload[4:36]
            inventory_vectors.append((vector_type, hash_bytes))
            payload = payload[36:]

        return {
            'magic': magic,
            'command': command,
            'payload_length': payload_length,
            'checksum': checksum,
            'inventory_vectors': inventory_vectors
        }

    except Exception as e:
        print(f"Error parsing 'inv' message: {e}")
        return None


def extract_block_hash_from_inv(inv_message):
    parsed_inv = parse_inv_message(inv_message)
    if parsed_inv and parsed_inv['command'] == 'inv':
        for inv in parsed_inv['inventory_vectors']:
            if inv[0] == 1:  # Inventory type 1 represents blocks
                # Return the hash of the first block encountered
                return inv[1].hex()
        # If no block hashes are found
        print("No block hashes found in the 'inv' message.")
        return None
    else:
        return None


def get_block_info(block_hash):
    try:
        print("Fetching block information...")
        response = requests.get(
            f"https://blockchain.info/rawblock/{block_hash}")
        if response.status_code == 200:
            block_data = response.json()
            print_block_data(block_data)
        else:
            print(
                f"Error retrieving block information. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error retrieving block information: {e}")
        return None


def print_block_data(block_data):
    print("************************************")
    print("Block Data")
    print("------------------------------------")
    print(f"Block Hash: {block_data['hash']}")
    print(f"Previous Block: {block_data['prev_block']}")
    print(f"Nonce: {block_data['nonce']}")
    print(f"Height: {block_data['height']}")
    print(f"Main Chain: {block_data['main_chain']}")
    date_time = datetime.datetime.fromtimestamp(block_data['time'])
    formatted_date = date_time.strftime("%A, %B %d, %Y - %H:%M:%S ")
    print(
        f"Mined At: {formatted_date}")
    print("************************************")


def main():
    socket_connection = connect_to_node()
    # Send version payload
    send_version_payload(socket_connection)
    # Send verack response
    send_verack(socket_connection)
    # Listen for events
    listen_for_events(socket_connection)


if __name__ == "__main__":
    main()
