import requests
import datetime


def get_block_info():
    block_hash = "00000000000000000002ee18a68752b7ede948778ec9a0ba2b1a79b4a5ea0203"
    try:
        # Query a blockchain explorer or a full node for block details
        print("Fetching block information...")
        response = requests.get(
            f"https://blockchain.info/rawblock/{block_hash}")
        if response.status_code == 200:
            block_data = response.json()
            block_time = block_data['time']
            # Convert block timestamp to date and time format
            block_datetime = datetime.utcfromtimestamp(
                block_time).strftime('%Y-%m-%d %H:%M:%S')
            print("Block Data")
            print(f"Block Hash: {block_data['hash']}")
            print(f"Previous Block: {block_data['prev_block']}")
            print(f"Nonce: {block_data['nonce']}")
            print(f"Time: {datetime(block_data['time'])}")
            return {
                'block_hash': "00000000000000000001fd09e640ed792e7512de3af125528d456685fe8972b2",
                # 'block_datetime': block_datetime
            }
        else:
            print(
                f"Error retrieving block information. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error retrieving block information: {e}")
        return None


get_block_info()
