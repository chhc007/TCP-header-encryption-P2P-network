import random

class SimonCipher:
    WORD_SIZE = 16
    KEY_WORDS = 4
    ROUNDS = 32
    Z_SEQUENCE = [0b0110111101111100]

    def __init__(self, key=None):
        if key is None:
            self.key = random.getrandbits(64)
        else:
            self.key = key

    def key_schedule(self):
        k = [(self.key >> (i * self.WORD_SIZE)) & ((1 << self.WORD_SIZE) - 1) for i in range(self.KEY_WORDS)]
        for i in range(self.ROUNDS - 1):
            tmp = (k[i+self.KEY_WORDS-1] << 3) & ((1 << self.WORD_SIZE) - 1) | (k[i+self.KEY_WORDS-1] >> (self.WORD_SIZE - 3))
            tmp = tmp ^ (k[i] >> 3) ^ (k[i] << (self.WORD_SIZE - 3)) ^ self.Z_SEQUENCE[i % len(self.Z_SEQUENCE)] ^ 3
            k.append(tmp & ((1 << self.WORD_SIZE) - 1))
        return k

    def encrypt(self, data):
        round_keys = self.key_schedule()
        x, y = data
        for i in range(self.ROUNDS):
            x, y = y ^ (x & ((x << 1) & ((1 << self.WORD_SIZE) - 1) | (x >> (self.WORD_SIZE - 1)))) ^ round_keys[i], x
        return x, y

    def decrypt(self, data):
        round_keys = self.key_schedule()
        x, y = data
        for i in range(self.ROUNDS - 1, -1, -1):
            x, y = y, x ^ (y & ((y << 1) & ((1 << self.WORD_SIZE) - 1) | (y >> (self.WORD_SIZE - 1)))) ^ round_keys[i]
        return x, y
