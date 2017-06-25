class Poly1305(object):
    """Poly1305 authenticator"""

    P = 0x3fffffffffffffffffffffffffffffffb  # 2^130-5

    def __init__(self, key):
        """Set the authenticator key"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        self.acc = 0
        self.r = int.from_bytes(key[0:16], 'little')
        self.r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        self.s = int.from_bytes(key[16:32], 'little')

    def create_tag(self, data):
        """Calculate authentication tag for data"""
        for i in range(0, len(data), 16):
            self.acc = self.r * (self.acc + int.from_bytes(data[i:i + 16] + b'\x01', 'little')) % self.P
        return (self.acc + self.s).to_bytes(17, 'little')[:16]
