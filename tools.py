import gnupg
import os
import pprint

class _GPG:
    """
    a factory that wrappers python-gnupg
    """
    def __init__(self, home=None):
        """
        a gpg instance load from `home`, default if `HOME/.gnupg`
        """
        if not home:
            home = os.getenv("HOME") + "/.gnupg"
        self.gpg = gnupg.GPG(gnupghome=home)


    def encrypt(self, msg, fingerprint):
        """
        encrypt `msg` with (receiver's) `fingerprint`, return encrypted **bytes data**
        """
        return self.gpg.encrypt(msg, fingerprint).data


    def decrypt(self, msg):
        """
        decrypt **byte data** `msg` with my private key
        return an decrypted **bytes data**
        """
        if type(msg) != type(b''):
            raise ValueError("msg should be a byte object!")

        return self.gpg.decrypt(msg).data


    def sign(self, msg):
        pass


    def verify(self, sig, fingerprint):
        pass


    def fingerprint(self):
        """ return the first fingerprint of this gpg instancde """
        return self.gpg.list_keys()[0]['fingerprint']


if __name__ == '__main__':
    # testing
    g = _GPG()

    pprint.pprint(g.gpg.list_keys())
    hidden = g.encrypt("test", g.fingerprint())
    pprint.pprint(hidden)
    pprint.pprint(g.decrypt(hidden))
