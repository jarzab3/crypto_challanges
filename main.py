import codecs

# Challenge 1
HEX_STRING = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
b64 = codecs.encode(codecs.decode(HEX_STRING, 'hex'), 'base64').decode()
# print(b64)


# Challenge 2

def xor_strings(s, t):
    """xor two strings together"""
    if isinstance(s, str):
        # Text strings contain single characters
        return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(s, t))
    else:
        # Python 3 bytes objects contain integer values in the range 0-255
        return bytes([a ^ b for a, b in zip(s, t)])


string1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
string2 = bytes.fromhex("686974207468652062756c6c277320657965")

cipherText = xor_strings(string1, string2)
print(cipherText.hex())

