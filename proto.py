"""
TiTs isn't Telegram, sorry.

This file is the implementation of the TiTs protocol

doc: https://ctlug.hackpad.com/TiTs-isnt-Telegram-sorry-TxiKrnafe2a

Client to server header
    length of the list   (special case: 1-to-1 = sender + receiver = 2)
    list of fingerprints
    message type: plaintext or encrypted

Client to client header (encrypted by sender's private key)
    timestamp
    serial number
    checksum
    message type (MIME: text/plain or not)
    life time (how long does a message show on the client UI)
    group ID (0 for 1-to-1 chatting)

payload (encrypted by receiver's public key)
    message body or attachment

"""

def _valid_key_list(key_list):
    """ check all keys are valid """
    if len(key_list) < 2:
        return False

    for k in key_list:
        if len(k) != 40:
        return False

    return True


class CSHeader:
    """ client to server header """
    def __init__(self, key_list, msg_type):
        """
        n: the length of the key list, min = 2
        key_list: list of fingerprints, each fingerprints is a string of length 40
        msg_type: 0 for plain text, 1 for encrypted text
        """

        if  _valid_key_list(key_list) and msg_type in [0, 1]:
            self.n = len(key_list)
            self.key_list = key_list
            self.msg_type = msg_type

        else:
            raise ValseError("invalid n or key_list")

    def encrypt(self):
        pass

    def encode(self):
        """ encode the object to bytes

        n: unsigned integer (4 bytes)
        key_list: 40*n char string
        msg_type: unsigned char (1 byte)
        """
        import struct
        return struct.pack("I{}sB".format(self.n), self.n, "".join(self.key_list), self.msg_type)

    def __del(self):
        pass


class CCHeader:
    """ client to client header """

    def __init__(self, sn, mime, life_time, gid):
        """ serial number, mine type, life time, group id """
        import time
        self.timestamp = time.time()
        self.sn = sn
        # XXX: implement packet checksum with binascii.crc32()
        # checksum for the payload or...?
        self.checksum = 0
        self.mime = mime
        self.life_time = life_time
        self.gid = gid

    def encrypt(self):
        pass

    def encode(self):
        """ encode the object to bytes

        timestamp: unsigned integer (4 bytes)
        serial number: unsigned integer (4 bytes)
        checksum: unsigned integer (4 bytes)
        mime type: string
        lifetime: integer (4 bytes), -1 for no specific
        gid: 32 char string
        """
        import struct
        return struct.pack("III{}si32s".format(len(self.mime)),
                self.timestamp, self.sn, self.checksum, self.mime, self.life_time, self.gid)


    def __del(self):
        pass


class CCPayload:
    """ client to client payload """
    def __init__(self, payload):
        if type(payload) == type(''):
            self.payload = payload.encode()
        else if type(payload) == type(b''):
            self.payload = payload
        else:
            raise ValseError('payload should be str or bytes')

    def encrypt(self):
        pass

    def encode(self):
        return self.payload

    def __del(self):
        pass


class TiTsProto:
    """ the TiTs protocol """
    def __init__(self):
        self.sn = 0

    def msg(self, n, key_list, msg_type, mine, life_time, gid, payload):
        """ return the byte object of the message """
        self.sn += 1
        cs_header = CSHeader(n, key_list, msg_type)
        cc_header = CCHeader(self.sn, mime, life_time, gid)
        cc_payload = CCPayload(payload)

        # XXX: checksum here?

        # if use the session for both in group chating
        # otherwise:
        # cc_header: sender's private key
        # cc_payload: receiver's public key

        # XXX: fill this part with gpg keys
        sender_pri = ""
        recv_pub = ""
        session_key = ""

        if cc_header.msg_type:
            if cs_header.n == 2:
                cc_header.encrypt(sender_pri)
                cc_payload.encrypt(recv_pub)

            else:
                cc_header.encrypt(session_key)
                cc_payload.encrypt(session_key)

        return cs_header.encode() + cc_header.encode() + cc_payload().encode()


    def __del__(self):
        pass
