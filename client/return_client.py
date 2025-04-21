import asyncio
import websockets
from tiny_aes import AES, pad, unpad

tyaes = AES()
IV = b'\x00' * 16
AES_KEY = [
    b'O\xca\xfd\x1f[\xaa=\x1a\xa4\x80\xc4}$q[p',
    b'\x92Z7\x11\x81m\xac5r[k\x13)\xf1V\t',
    b'\x8dq\x92t\xa9\x00\xc9\x04;Z\xfe\x15\xba7R ',
    b'\xea[\xdc\xe7\xc3\xaa\x8a\xeeN\xdb\x18\x9a\xe7\xdb\xd1\x9e',
    b'\xdc\x81/\x8bf\xb6}\xab\xa0\xa4\xbe\xd4c\x0e4:',
    b'-\xd5,\xa0\xca\x0e\xfd>\x16\x8f\xd2\xb5p9\xaf\x1e',
    b'\xba\xdd\xcc\x85\xd9\xd3\xf8\xbf\xf4\x06\xd4\x1f>\x08)!',
    b'(\x87\xfb\x94X\xbeT\x8a\x04\xfd\xb2\xef\xdd.JP',
    b')(\x9eO\x17 \xb7n?\xa7L\xfag\x19\x18p',
    b'\xf0P\xe3j-~\xa9:\x04V7u\x13v\x80\x1b',
    b',\xd1\xcc\xe1K\xc8\xd4\x91X\x18b\xd9uf\xcb\xe3',
    b'q0\xfc\x96bF|\x8dN\x97\xb0l\x05_d\xfd',
    b'\x17[6\xb2b=\xfdQ\x13\r\x01\xc7qK}J'
]

def get_message(message_hex):
    ciphertext_bytes = bytes.fromhex(message_hex)
    decrypted = tyaes.aes_decrypt_cbc(ciphertext_bytes, AES_KEY, IV)
    unpadded = unpad(decrypted)
    return unpadded.decode('utf-8')

async def connect_to_return(client_id):
    uri = "ws://localhost:8000/api/client/return"
    headers = {
        "clientId": str(client_id)
    }
    async with websockets.connect(uri, extra_headers=headers) as websocket:
        print (f"Connected to return endpoint as client {client_id}")
        try:
            while True:
                base_message = await websocket.recv()
                message = get_message(base_message)
                print (message)
        except websockets.ConnectionClosed:
            print ("Connection closed")

if __name__ == "__main__":
    client_id = int(input("Enter your client ID: "))
    asyncio.get_event_loop().run_until_complete(connect_to_return(client_id))
