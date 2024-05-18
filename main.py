import socket
import struct
import time
import hashlib
import requests
import datetime


def create_version_message():
    """
    Create a 'version' message for the Bitcoin protocol.

    This function constructs a 'version' message that is used in the Bitcoin protocol to announce
    information about the sending node. The message contains various pieces of information such as
    the protocol version, the services offered by the node, timestamps, addresses, and other details.

    Returns:
        bytes: The complete 'version' message ready to be sent over the network.
    """
    version = 70015  # Protocol version
    services = 0  # Node services (0 means no services)
    timestamp = int(time.time())  # Current timestamp
    addr_recv_services = services  # Services offered by the receiving node
    # Receiving node's IP address in binary format
    addr_recv_ip = socket.inet_aton('127.0.0.1')
    addr_recv_port = 8333  # Receiving node's port (default Bitcoin port)
    addr_trans_services = services  # Services offered by the transmitting node
    # Transmitting node's IP address in binary format
    addr_trans_ip = socket.inet_aton('127.0.0.1')
    addr_trans_port = 8333  # Transmitting node's port (default Bitcoin port)
    nonce = 0  # Random nonce (0 for simplicity)
    user_agent_bytes = 0  # User agent (0 means no user agent)
    start_height = 0  # Last block seen by the transmitting node
    relay = 0  # Whether to relay transactions (0 means false)

    # Pack address of the receiving node
    addr_recv = struct.pack('<Q16sH', addr_recv_services,
                            addr_recv_ip + b'\x00' * 10, addr_recv_port)
    # Pack address of the transmitting node
    addr_trans = struct.pack(
        '<Q16sH', addr_trans_services, addr_trans_ip + b'\x00' * 10, addr_trans_port)

    # Pack the payload of the version message
    payload = struct.pack('<LQQ26s26sQbL?', version, services, timestamp,
                          addr_recv, addr_trans, nonce, user_agent_bytes, start_height, relay)

    # Message header fields
    magic = struct.pack('<L', 0xD9B4BEF9)  # Network magic value
    command = b'version' + b'\x00' * 5  # Command name (padded to 12 bytes)
    length = struct.pack('<L', len(payload))  # Payload length
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[
        :4]  # Payload checksum

    # Complete message: header + payload
    message = magic + command + length + checksum + payload
    return message


def connect_to_node():
    """
    Connect to a Bitcoin node and send a 'version' message.

    This function establishes a TCP connection to a predefined Bitcoin node, creates a 'version' message 
    using the create_version_message() function, and sends this message to the node.

    Returns:
        socket.socket: The connected socket.
    """
    node_ip = 'seed.bitcoin.sipa.be'  # IP address of the Bitcoin node
    port = 8333  # Port number for the Bitcoin node (default Bitcoin port)

    # Create a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((node_ip, port))  # Connect to the node
    version_message = create_version_message()  # Create the 'version' message
    s.send(version_message)  # Send the 'version' message to the node

    return s  # Return the connected socket


def recv_message(s):
    """
    Receive a message from a Bitcoin node.

    This function receives a message from the connected Bitcoin node via the given socket.

    Args:
        s (socket.socket): The connected socket.

    Returns:
        bytes: The received message.
    """
    response = s.recv(1024)  # Receive up to 1024 bytes from the node
    return response  # Return the received message


def send_verack(s):
    """
    Send a 'verack' message to a Bitcoin node.

    This function constructs and sends a 'verack' (version acknowledgment) message to the connected Bitcoin node. 
    The 'verack' message is sent to acknowledge receipt of the 'version' message from the node.

    Args:
        s (socket.socket): The connected socket.
    """
    magic = struct.pack('<L', 0xD9B4BEF9)  # Network magic value
    command = b'verack' + b'\x00' * 6  # Command name (padded to 12 bytes)
    payload = b''  # The 'verack' message has an empty payload
    length = struct.pack('<L', len(payload))  # Payload length
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[
        :4]  # Payload checksum

    verack_message = magic + command + length + \
        checksum + payload  # Construct the 'verack' message
    s.send(verack_message)  # Send the 'verack' message to the node
    print("Verack Message sent")  # Print confirmation


def parse_header(data):
    """
    Parse the header of a Bitcoin network message.

    This function extracts and interprets the header information from a given Bitcoin network message.
    The header includes the magic value, command name, payload length, and checksum, along with the
    payload itself.

    Args:
        data (bytes): The raw data of the Bitcoin message.

    Returns:
        dict: A dictionary containing the parsed header fields and the payload, or None if parsing fails.
            - 'magic' (int): The network magic value.
            - 'command' (str): The command name.
            - 'length' (int): The length of the payload.
            - 'checksum' (bytes): The checksum of the payload.
            - 'payload' (bytes): The actual payload data.
    """
    try:
        # Unpack the header fields from the first 24 bytes of the data
        magic, command, length, checksum = struct.unpack('<L12sL4s', data[:24])
        # Remove padding null bytes and decode the command name to ASCII
        command = command.split(b'\x00', 1)[0].decode('ascii')

        # Return a dictionary with the parsed header fields and the payload
        return {
            'magic': magic,          # Network magic value
            'command': command,      # Command name
            'length': length,        # Payload length
            'checksum': checksum,    # Payload checksum
            'payload': data[24:24 + length]  # Payload data
        }
    except Exception as e:
        # Print an error message if parsing fails
        print(f"Failed to parse header: {e}")
        return None


def parse_version_payload(payload):
    """
    Parse the payload of a Bitcoin 'version' message.

    This function extracts and interprets the data from the payload of a Bitcoin 'version' message.
    The payload contains various fields such as protocol version, services, timestamp, network addresses,
    nonce, user agent, starting block height, and relay flag.

    Args:
        payload (bytes): The payload of the 'version' message.

    Returns:
        dict: A dictionary containing the parsed fields from the payload, or None if parsing fails.
            - 'version' (int): The protocol version.
            - 'services' (int): The services offered by the node.
            - 'timestamp' (int): The timestamp when the message was sent.
            - 'addr_recv' (bytes): The network address of the receiving node.
            - 'addr_trans' (bytes): The network address of the transmitting node.
            - 'nonce' (int): A random nonce used to detect connections to self.
            - 'user_agent' (str): The user agent of the node.
            - 'start_height' (int): The starting block height of the node.
            - 'relay' (int): Whether the node wants to relay transactions (0 or 1).
    """
    try:
        # Unpack version, services, and timestamp from the first 20 bytes
        version, services, timestamp = struct.unpack('<LQq', payload[:20])

        # Extract the receiving and transmitting addresses from the next 52 bytes
        addr_recv = payload[20:46]
        addr_trans = payload[46:72]

        # Unpack nonce from the next 8 bytes
        nonce, = struct.unpack('<Q', payload[72:80])

        # Extract the length of the user agent string
        user_agent_bytes = payload[80]
        user_agent_start = 81
        user_agent_end = user_agent_start + user_agent_bytes

        # Validate user agent length
        if user_agent_end > len(payload):
            raise ValueError("Invalid user agent length")

        # Extract and decode the user agent string
        user_agent = payload[user_agent_start:user_agent_end].decode('ascii')
        remaining_payload = payload[user_agent_end:]

        # Validate the remaining payload length for start_height and relay
        if len(remaining_payload) < 5:
            raise ValueError("Insufficient bytes for start_height and relay")

        # Unpack start_height and relay from the remaining payload
        start_height, relay = struct.unpack('<Lb', remaining_payload[:5])

        # Return a dictionary with the parsed fields
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
        # Handle struct-related unpacking errors
        print(f"Struct error: {e}")
    except ValueError as e:
        # Handle value-related errors
        print(f"Value error: {e}")

    # Return None if parsing fails
    return None


def parse_addr(addr):
    """
    Parse a Bitcoin network address.

    This function extracts and interprets the components of a Bitcoin network address from the given binary data.
    The address contains information about the services offered by the node, its IP address, and port number.

    Args:
        addr (bytes): The raw bytes representing the Bitcoin network address.

    Returns:
        dict: A dictionary containing the parsed address fields.
            - 'services' (int): The services offered by the node.
            - 'ip' (str): The IP address of the node.
            - 'port' (int): The port number of the node.
    """
    # Unpack the address components from the binary data
    services, ip, port = struct.unpack('<Q16sH', addr)

    # Convert the IP address from binary format to a readable string
    ip = socket.inet_ntoa(ip[:4])

    # Return a dictionary with the parsed address fields
    return {
        'services': services,  # Services offered by the node
        'ip': ip,              # IP address of the node
        'port': port           # Port number of the node
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
    """
    Send a 'version' message payload to a Bitcoin node.

    This function sends a 'version' message payload to a connected Bitcoin node via the provided socket.

    Args:
        s (socket.socket): The connected socket to the Bitcoin node.
    """
    # Subscribe to events by sending a 'version' message to the node
    version_message = create_version_message()  # Create the 'version' message
    s.send(version_message)  # Send the 'version' message to the node


def handle_inv_payload(payload, s):
    """
    Handle an 'inv' payload received from a Bitcoin node.

    This function extracts inventory vectors from the 'inv' payload received from a Bitcoin node, 
    and requests detailed information for each inventory vector using the 'getdata' payload.

    Args:
        payload (bytes): The raw bytes representing the 'inv' payload.
        s (socket.socket): The connected socket to the Bitcoin node.
    """
    # Extract the number of inventory vectors from the 'inv' payload
    num_inventory = struct.unpack('<B', payload[4:5])[0]

    # Initialize an empty list to store inventory vectors
    inventory_list = []

    # Iterate through each inventory vector in the payload
    for i in range(num_inventory):
        # Extract each inventory vector
        inventory_vector = payload[5 + i * 36: 5 + (i + 1) * 36]
        inventory_list.append(inventory_vector)

    # Request detailed information for each inventory vector using the 'getdata' payload
    request_detailed_info(s, inventory_list)


def request_detailed_info(s, inventory_vectors):
    """
    Request detailed information for each inventory vector from a Bitcoin node.

    This function constructs and sends a 'getdata' payload to request detailed information 
    for each inventory vector from a Bitcoin node via the provided socket.

    Args:
        s (socket.socket): The connected socket to the Bitcoin node.
        inventory_vectors (list): A list of inventory vectors for which detailed information is requested.
    """
    # Initialize an empty payload
    payload = b''

    # Iterate through each inventory vector
    for inventory_vector in inventory_vectors:
        # Add the request for a block (type code 1) and the hash of the block to the payload
        payload += struct.pack('<L', 1)  # Requesting a block
        payload += inventory_vector[4:]  # Hash of the block

    # Construct the 'getdata' message
    command = b'getdata' + b'\x00' * 5  # Command name (padded to 12 bytes)
    length = struct.pack('<L', len(payload))  # Payload length
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[
        :4]  # Payload checksum

    # Create the 'getdata' message
    getdata_message = create_message(command, length, checksum, payload)

    # Send the 'getdata' message to the Bitcoin node via the provided socket
    s.send(getdata_message)


def create_message(command, length, checksum, payload):
    """
    Create a Bitcoin network message.

    This function constructs a Bitcoin network message by concatenating the provided components.

    Args:
        command (bytes): The command name.
        length (bytes): The length of the payload.
        checksum (bytes): The checksum of the payload.
        payload (bytes): The payload data.

    Returns:
        bytes: The complete Bitcoin network message.
    """
    # Concatenate the command, length, checksum, and payload to form the complete message
    return command + length + checksum + payload


def listen_for_events(s):
    """
    Listen for events from a Bitcoin node.

    This function continuously listens for incoming events (e.g., 'inv' payloads) from a Bitcoin node via the provided socket.
    When an event is received, it checks the message header to determine the type of event. If the event is an 'inv' payload,
    it handles the payload and requests detailed information for each inventory vector. Otherwise, it prints a message indicating
    that the message type is unhandled.

    Args:
        s (socket.socket): The connected socket to the Bitcoin node.
    """
    while True:
        # Continuously listen for incoming events (inv payloads)
        message = recv_message(s)  # Receive a message from the Bitcoin node
        if message:
            print("")
            print("Received message...")
            # Parse the header of the received message
            message_header = parse_header(message)
            print("Message Header")
            print("-----------------")
            print(message_header)  # Print the message header
            if message_header['command'] == 'inv':
                handle_inv_payload(message, s)  # Handle the 'inv' payload
                # Extract block hashes from the 'inv' payload
                block_hash = extract_block_hash_from_inv(message)
                # Get detailed information for each block hash
                get_block_info(block_hash)
            else:
                # Print a message indicating an unhandled message type
                print("Unhandled message type")


def parse_inv_message(message):
    """
    Parse an 'inv' message received from a Bitcoin node.

    This function parses the components of an 'inv' message received from a Bitcoin node,
    verifies its integrity using the checksum, and extracts the inventory vectors from the payload.

    Args:
        message (bytes): The raw bytes representing the 'inv' message.

    Returns:
        dict: A dictionary containing the parsed message components and inventory vectors,
              or None if parsing fails.
            - 'magic' (bytes): The network magic value.
            - 'command' (str): The command name.
            - 'payload_length' (int): The length of the payload.
            - 'checksum' (bytes): The checksum of the payload.
            - 'inventory_vectors' (list): A list of tuples containing inventory vectors,
                                           each tuple consisting of a vector type and hash bytes.
    """
    try:
        # Check if the message is at least 36 bytes long (minimum length for an inventory vector)
        if len(message) < 36:
            raise ValueError("Incomplete 'inv' message")

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
            if len(payload) < 36:
                raise ValueError("Incomplete inventory vector")
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
    """
    Extract block hashes from an 'inv' message received from a Bitcoin node.

    This function parses the 'inv' message, extracts block hashes from the inventory vectors,
    and returns the hash of the first block encountered.

    Args:
        inv_message (bytes): The raw bytes representing the 'inv' message.

    Returns:
        str: The hash of the first block encountered, or None if no block hashes are found.
    """
    parsed_inv = parse_inv_message(inv_message)  # Parse the 'inv' message
    # Check if the message is an 'inv' message
    if parsed_inv and parsed_inv['command'] == 'inv':
        # Iterate through inventory vectors
        for inv in parsed_inv['inventory_vectors']:
            if inv[0] == 1:  # Check if the inventory type is for blocks
                # Return the hash of the first block encountered
                return inv[1].hex()
        # If no block hashes are found
        print("No block hashes found in the 'inv' message.")
        return None
    else:
        return None


def get_block_info(block_hash):
    """
    Retrieve information for a specific block from the blockchain.

    This function fetches information for a block with the given hash from the blockchain.info API
    and prints the retrieved block data.

    Args:
        block_hash (str): The hash of the block for which information is to be retrieved.

    Returns:
        dict or None: A dictionary containing the block data if retrieval is successful, 
                      otherwise None.
    """
    try:
        print("Fetching block information...")

        # Send a GET request to the blockchain.info API to retrieve block information
        response = requests.get(
            f"https://blockchain.info/rawblock/{block_hash}")

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the JSON response to extract block data
            block_data = response.json()
            # Print the retrieved block data
            print_block_data(block_data)
            # Return the block data
            return block_data
        else:
            # If the request was not successful, print an error message with the status code
            print(
                f"Error retrieving block information. Status code: {response.status_code}")
            return None
    except Exception as e:
        # If an exception occurs during retrieval, print an error message
        print(f"Error retrieving block information: {e}")
        return None


def print_block_data(block_data):
    """
    Print information about a block.

    This function prints various details about a block using the provided block data.

    Args:
        block_data (dict): A dictionary containing information about a block.

    Returns:
        None
    """
    print("************************************")
    print("Block Data")
    print("------------------------------------")
    print(f"Block Hash: {block_data['hash']}")
    print(f"Previous Block: {block_data['prev_block']}")
    print(f"Nonce: {block_data['nonce']}")
    print(f"Height: {block_data['height']}")
    print(f"Main Chain: {block_data['main_chain']}")

    # Convert the timestamp to a human-readable format
    date_time = datetime.datetime.fromtimestamp(block_data['time'])
    formatted_date = date_time.strftime("%A, %B %d, %Y - %H:%M:%S ")
    print(f"Mined At: {formatted_date}")

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
