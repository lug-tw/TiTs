import gnupg
import os
import pprint

MIT_KEY_SERVER = 'hkp://pgp.mit.edu'

class _GPG:
    """
    a factory that wrappers python-gnupg
    Note: most of input / output are byte data
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
        encrypt `msg` with (receiver's) `fingerprint`, return encrypted message

        @msg: byte data
        @return: byte data
        """

        if type(msg) != type(b''):
            raise ValueError("msg should be a byte object!")

        if type(fingerprint) != type('') or len(fingerprint) != 40:
            raise ValueError("invalid fingerprint!")

        return self.gpg.encrypt(msg, fingerprint).data


    def decrypt(self, msg):
        """
        decrypt **byte data** `msg` with my private key, return decrypted message

        @msg: byte data
        @return: byte data
        """

        if type(msg) != type(b''):
            raise ValueError("msg should be a byte object!")

        return self.gpg.decrypt(msg).data


    def sign(self, msg):
        """
        sign `msg` with my private key, return `msg+signature`

        @msg: byte data
        @return: byte data
        """

        if type(msg) != type(b''):
            raise ValueError("msg should be a byte object!")

        return self.gpg.sign(msg)


    def verify(self, sig, fingerprint):
        """
        verify `sig` with `fingerprint`
        Note: `fingerprint` should be available on MIT_KEY_SERVER

        @sig: byte data
        @return: byte data
        """

        if type(sig) != type(b''):
            raise ValueError("msg should be a byte object!")

        if type(fingerprint) != type('') or len(fingerprint) != 40:
            raise ValueError("invalid fingerprint!")


        try:
            self.gpg.recv_keys(MIT_KEY_SERVER, fingerprint)

        except:
            raise ValueError("error when receiving fingerprint {}".format(fingerprint))

        return self.gpg.verify(sig).valid


    def fingerprint(self):
        """ return the **first** fingerprint of this gpg instancde """
        return self.gpg.list_keys()[0]['fingerprint']


if __name__ == '__main__':
    # testing
    g = _GPG()

    pprint.pprint(g.gpg.list_keys())
    hidden = g.encrypt("test", g.fingerprint())
    pprint.pprint(hidden)
    pprint.pprint(g.decrypt(hidden))


    """
    debugging in IPython shell...
    a = gnupg.GPG(gnupghome='test')
    a.gen_key(a.gen_key_input(name_real='blah', name_email='gg@inin.de'))

    """
