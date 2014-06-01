"""
TiTs isn't Telegram, sorry.

This file is the implementation of the TiTs protocol

doc: https://ctlug.hackpad.com/TiTs-isnt-Telegram-sorry-TxiKrnafe2a

Client to server header
    message type: plaintext or encrypted
    length of the list   (special case: 1-to-1 = sender + receiver = 2)
    list of fingerprints

Client to client header (encrypted by sender's private key)
    timestamp
    serial number
    checksum
    life time (how long does a message show on the client UI)
        <= 0 second means display forever
    group ID (0 for 1-to-1 chatting)
    message type (MIME: text/plain or not)

payload (encrypted by receiver's public key)
    message body or attachment

"""
import binascii
import hashlib
import random
import struct
import time

def _valid_key_list(key_list):
    """ check all keys are valid """
    if len(key_list) < 2:
        return False

    for k in key_list:
        if len(k) != 40:
            return False

    return True

def _msg_encrypt(msg, key):
    """ encrypt message with key """
    # XXX: which algorithm should we use?
    return msg


class CSHeader:
    """ client to server header """
    def __init__(self, msg_type, key_list):
        """
        msg_type: 0 for plain text, 1 for encrypted text
        n: the length of the key list, min = 2
        key_list: list of fingerprints, each fingerprints is a string of length 40
        """

        if  _valid_key_list(key_list) and msg_type in [0, 1]:
            self.msg_type = msg_type
            self.n = len(key_list)
            self.key_list = key_list

        else:
            raise ValueError("invalid key_list or msg_type")


    def __repr__(self):
        return "msg_type: {} n: {} \nkey_list: [{}]".format(
               "encrypted" if self.msg_type else "plain text",
               self.n,
               ", ".join(self.key_list))


    def encode(self):
        """ encode the object to bytes

        msg_type: unsigned char (1 byte)
        n: unsigned integer (4 bytes)
        key_list: 40*n char string
        """
        return struct.pack("BI{}s".format(self.n*20), self.msg_type, self.n,
               b''.join([binascii.unhexlify(x) for x in self.key_list]))


    def __del(self):
        pass


class CCHeader:
    """ client to client header """

    def __init__(self, sn, life_time, gid, mime):
        """ serial number, life time, group id, mime """
        self.timestamp = time.time()
        self.sn = sn
        self.checksum = 0
        self.life_time = life_time
        self.gid = hashlib.md5(( gid +
                        str(int(time.time()) +
                            int(random.random() * 55665566))
                        ).encode()).hexdigest().encode()
        self.mime = mime


    def __repr__(self):
        return ("timestamp: {} serial number: {} checksum: {}\n" + \
               "life_time: {} gid: {} mime: {}").format(
               self.timestamp, self.sn, self.checksum,
               self.life_time, self.gid, self.mime)


    def encode(self):
        """ encode the object to bytes

        timestamp: unsigned integer (4 bytes)
        serial number: unsigned integer (4 bytes)
        checksum: unsigned integer (4 bytes)
        lifetime: integer (4 bytes), -1 for no specific
        gid: 32 char string
        mime type: string
        """
        return struct.pack("fIIi32s{}s".format(len(self.mime)),
                self.timestamp, self.sn, self.checksum,
                self.life_time, self.gid, self.mime.encode())


    def __del(self):
        pass


class CCPayload:
    """ client to client payload """
    def __init__(self, payload):
        if type(payload) == type(''):
            self.payload = payload.encode()
        elif type(payload) == type(b''):
            self.payload = payload
        else:
            raise ValueError('payload should be str or bytes')


    def __repr__(self):
        return payload

    def encode(self):
        return self.payload

    def __del(self):
        pass


class TiTsProto:
    """ the TiTs protocol """
    def __init__(self):
        self.sn = 0
        self.session_key = b''

    def msg(self, n, key_list, msg_type, mime, life_time, gid, payload):
        """ return the byte object (packet) of the message """

        if not gid or type(gid) != type(''):
            gid = "1to1"


        self.sn += 1
        cs_header = CSHeader(msg_type, key_list)
        cc_header = CCHeader(self.sn, life_time, gid, mime)
        cc_payload = CCPayload(payload)
        cc_header.checksum = binascii.crc32(cc_payload.payload)

        # all secure chat would be encrypted by the session key

        outer = cs_header.encode()
        inner = cc_header.encode() + cc_payload.encode()

        if cs_header.msg_type:
            inner = _msg_encrypt(inner, self.session_key)

        packet = outer + inner
        print("len = {}".format(len(packet)))

        return  struct.pack("I", len(packet)) + packet


    def decode(self):
        pass

    def __del__(self):
        pass

# testing
if __name__ == '__main__':
    test_kl = ["7DD0628E6DB8D86466355BC094ABA8A15C7CC0BD",
               "4ADD956CEF0703D685F2C1619A1C3CC9FBD057FC",
               "D4E85D0DD0A59B4DFC91E71246526187F24D9E37",
               "0B00B6BD1771B19E5B93902239A3B1BED944E4AB",
               "B9A41E15A020D3CCF57A344BDA698A7F1B36B96F",
               "69C9EC0C61A2F0C09DE296EB86F272230F1A804E",
               "731B667E876258C9C946A7BF8ADE717C4726E54D",
               "B66F3F18CEDA9D98EAC8844A63604D621DE9422B",
               "607CB83DEA39F8382AF6CD95404FC0F0BC577A6E",
               "0BDE82D3C6F2D4B41C0835A71D9893C4D8179092",
               "602AD0A234EBFD13C7A81DFC48290D28562794F3",
               "E7EC50252A41E6A9EDCB8A45A7413FD2504CF729",
               "6CE565A4C2827E2C1B1FAC967ED8CD2F8049AC8B",
               "5B2614662E4329E3433B3FEFE2A9EC26D765B010",
               "A79A5FF7928432BD343E297CCB86B80E16F00F5D",
               "D91FFE1E2266E5EC08182CCF2E040829F3F41888"]

    # for i in range(16):
    #     # 1
    #     # print(_valid_key_list(test_kl[:i]))

    #     # 2
    #     try:
    #         cs_h = CSHeader(1, test_kl[:i])
    #         print(cs_h)
    #         print("->", end="")
    #         print(cs_h.encode())
    #     except ValueError as e:
    #         print(i, e)

    # 3
    # for i in range(10):
    #     mime = "text/blah{}".format(i)
    #     cc_h = CCHeader(i, -1+i, "1to1", mime)
    #     cc_h.checksum = binascii.crc32(b'blah')
    #     print(cc_h)
    #     print(cc_h.encode())

    # 4
    # tit = TiTsProto()
    # print(tit.msg(2, test_kl[:], 0, "text/plain", 1, None, b'5566'))
    print("done")
