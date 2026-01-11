import random

class RSACipher:
    def __init__(self, key_size=1024):
        self.e = 65537
        self.n = 0
        self.d = 0
        self.key_size = key_size
        self._generate_keys()

    def _is_prime(self, n, k=5):
        if n < 2: return False
        if n in (2, 3): return True
        if n % 2 == 0: return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _generate_large_prime(self):
        while True:
            num = random.getrandbits(self.key_size // 2)
            num |= (1 << (self.key_size // 2 - 1)) | 1
            if self._is_prime(num):
                return num

    def _generate_keys(self):
        p = self._generate_large_prime()
        q = self._generate_large_prime()
        self.n = p * q
        phi = (p - 1) * (q - 1)
        self.d = pow(self.e, -1, phi)

    def encrypt(self, plaintext: str) -> int:
        m_int = int.from_bytes(plaintext.encode('utf-8'), 'big')
        if m_int >= self.n:
            raise ValueError("Message too large for key size")
        return pow(m_int, self.e, self.n)

    def decrypt(self, ciphertext: int) -> str:
        m_int = pow(ciphertext, self.d, self.n)
        num_bytes = (m_int.bit_length() + 7) // 8
        return m_int.to_bytes(num_bytes, 'big').decode('utf-8')

if __name__ == "__main__":
    rsa = RSACipher()
    message = "Math is Elegant"
    
    encrypted = rsa.encrypt(message)
    decrypted = rsa.decrypt(encrypted)
    
    print(f"Original: {message}")
    print(f"Encrypted: {encrypted}")

    print(f"Decrypted: {decrypted}")
