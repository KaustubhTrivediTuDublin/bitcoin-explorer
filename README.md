# Bitcoin Explorer

This code is a Python script designed to interact with a Bitcoin node, adhering to the Bitcoin network protocol. It performs several key actions: connecting to a node, sending version and acknowledgment messages, receiving messages from the node, and handling inventory messages to request detailed block information.
Run this code:
```bash
python main.py
```
Here's a breakdown of the code:
## 1. Imports

The script imports several standard Python libraries:

- `socket`: for network communication.
- `struct`: for packing and unpacking binary data.
- `time`: for timestamps.
- `hashlib`: for creating checksums.
- `requests`: for making HTTP requests.
- `datetime`: for handling date and time.

## 2. Creating the Version Message

The `create_version_message` function constructs a version message according to the Bitcoin protocol. The version message includes various fields like version number, services, timestamp, and addresses.

- **Packing Data**: Data is packed using the `struct` library to conform to the protocol's binary format.
- **Checksum**: A checksum is calculated using double SHA-256 hashing.
- **Message Construction**: The message is constructed by concatenating the magic number, command, payload length, checksum, and payload.

## 3. Connecting to a Node

The `connect_to_node` function creates a TCP connection to a Bitcoin node (in this case, `seed.bitcoin.sipa.be` on port `8333`).

- **Socket Connection**: Establishes a connection using the `socket` library.
- **Sending Version Message**: Sends the version message to the node.

## 4. Receiving Messages

The `recv_message` function receives a message from the connected node. It reads up to 1024 bytes of data.

## 5. Sending Verack Message

The `send_verack` function constructs and sends a "verack" message to acknowledge the receipt of the version message.

## 6. Parsing Headers and Payloads

Several functions parse the headers and payloads of messages:

- **`parse_header`**: Extracts and decodes the header components.
- **`parse_version_payload`**: Decodes the payload of a version message.
- **`parse_addr`**: Parses address fields from the payload.

## 7. Handling Inventory Messages

- **`handle_inv_payload`**: Extracts inventory vectors from an "inv" message and requests detailed information for each.
- **`request_detailed_info`**: Constructs and sends a "getdata" message to request detailed block information.
- **`parse_inv_message`**: Parses an "inv" message to extract inventory vectors.
- **`extract_block_hash_from_inv`**: Extracts block hashes from an inventory message.

## 8. Fetching and Printing Block Information

- **`get_block_info`**: Uses the `requests` library to fetch block information from a public blockchain API.
- **`print_block_data`**: Prints detailed block information in a formatted manner.

## 9. Listening for Events

The `listen_for_events` function continuously listens for incoming messages, handles "inv" messages, and fetches block information.

## 10. Main Function

The `main` function coordinates the script's flow:

- Connects to the node.
- Sends the version payload.
- Sends the verack message.
- Listens for events.

## 11. Entry Point

The `if __name__ == "__main__":` block ensures the `main` function is called when the script is run directly.

## Example Execution Flow

1. **Connect to Node**: Establish a connection to a Bitcoin node.
2. **Send Version Message**: Notify the node of the client's version.
3. **Receive Messages**: Wait for responses from the node.
4. **Send Verack**: Acknowledge the version message.
5. **Handle Inventory Messages**: Request detailed block information from inventory messages.
6. **Fetch and Print Block Data**: Retrieve and display block information from a public API.

This script demonstrates basic interaction with the Bitcoin protocol, handling version negotiation, acknowledgment, and inventory message processing to fetch detailed block data from a Bitcoin node.
