"""IDC (inter-device control) message framing for the Wimp/SIDESYNC channel.

Static source: dexonpc i2/* (TcpCmd text "Length Seq MainCmd SubCmd Type Info",
Java writeUTF framing, Base64) and g2/a (session AES-CBC via
CryptoppNativeManager). The AES-CBC key/IV/PKCS7 are the SAME session codec the
main channel uses (main_channel.ControlCodec), already validated live by the
encrypted TerminalInfo/PSS exchanges. No device or network I/O here.
"""
import base64
import struct

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from main_channel import IV

SEP = "/&%"
MAX_UTF = 0xffff


def _aes_encrypt(key, text):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("session key must be 32 bytes")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(text.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(IV)).encryptor()
    return enc.update(padded) + enc.finalize()


def _aes_decrypt(key, cipher):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("session key must be 32 bytes")
    if not isinstance(cipher, bytes) or not cipher or len(cipher) % 16:
        raise ValueError("invalid ciphertext length")
    dec = Cipher(algorithms.AES(key), modes.CBC(IV)).decryptor()
    padded = dec.update(cipher) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")


def connect_info(listener_port, device_id="<lab>", device="<lab>", net="USB",
                 name="<lab>"):
    # o2/a WimpDevice.parse expects >=8 "/&%" fields; field[0] = the port the
    # phone will dial back (Integer.parseInt). The rest are device identity it
    # stores. No spaces (the IDC text is space-tokenised).
    if not isinstance(listener_port, int) or not 1 <= listener_port <= 65535:
        raise ValueError("listener_port must be a uint16")
    fields = [str(listener_port), "0", device_id, "false", "2.4.1.27", device, net, name]
    info = SEP.join(fields)
    if " " in info:
        raise ValueError("connect info must not contain spaces")
    return info


def command_text(main_cmd, sub_cmd, type_, info, seq=1):
    if not 0 <= seq <= 32760:
        raise ValueError("seq out of range")
    return "%d %d %s %s %s %s" % (len(info), seq, main_cmd, sub_cmd, type_, info)


def encode(key, text):
    """writeUTF( Base64( AES-CBC(text) ) ): 2-byte big-endian length + ASCII."""
    blob = base64.b64encode(_aes_encrypt(key, text))
    if len(blob) > MAX_UTF:
        raise ValueError("IDC frame too large for writeUTF")
    return struct.pack(">H", len(blob)) + blob


def decode(key, data):
    """Inverse of encode; a >5-token plaintext frame (e.g. ALIVE_CHECK) is returned raw."""
    if len(data) < 2:
        raise ValueError("short IDC frame")
    length = struct.unpack_from(">H", data, 0)[0]
    body = data[2:2 + length]
    if len(body) != length:
        raise ValueError("truncated IDC frame")
    text = body.decode("ascii", "strict")
    if len(text.split(" ")) > 5:
        return text
    return _aes_decrypt(key, base64.b64decode(text, validate=True))


def sidesync_conn_request(key, listener_port, seq=1):
    return encode(key, command_text("CONNECT", "SIDESYNC_CONN", "REQUEST",
                                     connect_info(listener_port), seq))


def sidesync_conn_response(key, data):
    """Strict encrypted, single-response parser; retain only status/control port.

    No plaintext fallback. A valid response is not proof of a connect-back.
    Java Info length counts UTF-16 code units, not Unicode code points.
    """
    message = encrypted_message(key, data)
    if (message["main"], message["sub"], message["type"]) != ("CONNECT", "SIDESYNC_CONN", "RESPONSE"):
        raise ValueError("unexpected IDC reply envelope")
    info = message["info"]
    sequence = message["sequence"]
    if info in ("BUSY", "INVALID"):
        return dict(accepted=False, reason=info, sequence=sequence)
    parts = info.split(SEP)
    if len(parts) < 8 or not parts[0].isascii() or not parts[0].isdecimal():
        raise ValueError("invalid IDC reply connectInfo")
    port = int(parts[0])
    if not 1 <= port <= 65535:
        raise ValueError("invalid IDC CONTROL port")
    return dict(accepted=True, control_port=port, sequence=sequence)


def encrypted_message(key, data):
    """Exactly one encrypted IDC writeUTF message; no plaintext fallback."""
    if len(data) < 2 or len(data) != 2 + struct.unpack_from(">H", data)[0]:
        raise ValueError("IDC reply must contain exactly one complete writeUTF")
    text = _aes_decrypt(key, base64.b64decode(data[2:], validate=True))
    fields = text.split(" ", 5)
    if len(fields) != 6:
        raise ValueError("invalid IDC envelope")
    length, sequence = fields[:2]
    if not length.isascii() or not length.isdecimal() or not sequence.isascii() or not sequence.isdecimal():
        raise ValueError("invalid IDC reply counters")
    if not 0 <= int(sequence) <= 32760 or int(length) != len(fields[5].encode("utf-16-be")) // 2:
        raise ValueError("invalid IDC reply length/sequence")
    return dict(main=fields[2], sub=fields[3], type=fields[4],
                sequence=int(sequence), info=fields[5])
