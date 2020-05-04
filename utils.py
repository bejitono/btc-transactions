import hashlib
import struct
import unittest

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_check_encode(version, payload):
    s = chr(version) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leading_zeroes = countLeadingChars(result, '\0')
    return '1' * leading_zeroes + base58_encode(base58_decode(result))

def base58_check_decode(s):
    leadingOnes = countLeadingChars(s, '1')
    s = base58_encode(base256_decode(s))
    result = '\0' * leadingOnes + s[:-4]
    chk = s[-4:]
    checksum = hashlib.sha256(hashlib.sha256(result).digest()).digest()[0:4]
    assert(chk == checksum)
    version = result[0]
    return result[1:]

def base58_encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n /= 58
    return result

def base58_decode(s):
    result = 0
    for i in range(0, len(s)):
        result = result * 58 + b58.index(s[i])
    return result

def base256_encode(n):
    result = ''
    while n > 0:
        result = chr(n % 256) + result
        n /= 256
    return result

def base256_decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
    return result


def countLeadingChars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count


class TestUtils(unittest.TestCase):
    """
    def test_varint(self):
        self.assertEqual(varint(0x42), '\x42')
        self.assertEqual(varint(0x123), '\xfd\x23\x01')
        self.assertEqual(varint(0x12345678), '\xfe\x78\x56\x34\x12')
        self.assertEqual(processVarInt(varint(0x42)), [0x42, 1])
        self.assertEqual(processVarInt(varint(0x1234)), [0x1234, 3])

    def test_varstr(self):
        self.assertEqual(varstr('abc'), '\x03abc')
        self.assertEqual(processVarStr('\x03abc'), ['abc', 4])

    def test_processAddr(self):
        self.assertEqual(processAddr('x'*20 + '\x62\x91\x98\x16\x20\x8d'),
                         '98.145.152.22:8333')
    """

    def test_countLeadingCharacters(self):
        self.assertEqual(countLeadingChars('a\0bcd\0', '\0'), 0)
        self.assertEqual(countLeadingChars('\0\0a\0bcd\0', '\0'), 2)        
        self.assertEqual(countLeadingChars('1a\0bcd\0', '1'), 1)

    def test_base256(self):
        self.assertEqual(base58_encode(base58_decode('abc')), 'abc')
        self.assertEqual(base58_encode(0x4142), 'AB')
        self.assertEqual(base58_encode('AB'), 0x4142)

    def test_base58(self):
        self.assertEqual(base58_encode(base58_decode('abc')), 'abc')
        self.assertEqual(base58_encode('121'), 58)
        self.assertEqual(base58_encode('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'),
            0x800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D)

    def test_base58check(self):
        self.assertEqual(base58_check_decode(base58_check_encode(42, 'abc')), 'abc')
        self.assertEqual(base58_check_decode(base58_check_encode(0, '\0\0abc')), '\0\0abc')
        s = base58_encode(0x0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D)
        b = base58_check_encode(0x80, s)
        self.assertEqual(b, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")

if __name__ == '__main__':
    unittest.main()