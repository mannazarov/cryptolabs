from main import *


def test_encrypt_ecb():
    key = b'sixteen-byte-key'
    msg = b'sixteen-byte-msgsixteen-byte-msgsixteen-'

    pad_msg = pad(msg, BLOCK_SIZE, style='pkcs7')
    aes = AES.new(key, AES.MODE_ECB)
    cipher_text1 = aes.encrypt(pad_msg)

    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('ECB')
    cipher_text2 = ciph.encrypt(msg)

    print('==============ECB_ENCRYPT_TEST===============')
    print("AES   : ", cipher_text1.hex())
    print("MANUAL: ", cipher_text2.hex())
    assert cipher_text1 == cipher_text2


def test_encrypt_cbc():
    key = b'sixteen-byte-key'
    msg = b'sixteen-byte-msgsixteen-byte-msgsixteen-'
    iv = b'sixteen-byte-iv-'
    pad_msg = pad(msg, BLOCK_SIZE, style='pkcs7')
    aes = AES.new(key, AES.MODE_CBC, iv)
    cipher_text1 = aes.encrypt(pad_msg)

    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('CBC')
    ciph.set_iv(iv)
    cipher_text2 = ciph.encrypt(msg, iv)

    print('==============CBC_ENCRYPT_TEST===============')
    print("AES:    ", cipher_text1.hex())
    print("MANUAL: ", cipher_text2.hex())
    assert cipher_text1 == cipher_text2


def test_encrypt_cfb():
    key = b'sixteen-byte-key'
    msg = b'sixteen-byte-msgsixteen-byte-msgsixteen-'
    iv = b'sixteen-byte-iv-'
    aes = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    cipher_text1 = aes.encrypt(msg)

    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('CFB')
    cipher_text2 = ciph.encrypt(msg, iv)

    print('==============CFB_ENCRYPT_TEST===============')
    print("AES:    ", cipher_text1.hex())
    print("MANUAL: ", cipher_text2.hex())
    assert cipher_text1 == cipher_text2


def test_encrypt_ofb():
    key = b'sixteen-byte-key'
    msg = b'sixteen-byte-msgsixteen-byte-msgsixteen-'
    iv = b'sixteen-byte-iv-'
    aes = AES.new(key, AES.MODE_OFB, iv)
    cipher_text1 = aes.encrypt(msg)

    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('OFB')
    cipher_text2 = ciph.encrypt(msg, iv)

    print('==============OFB_ENCRYPT_TEST===============')
    print("AES:    ", cipher_text1.hex())
    print("MANUAL: ", cipher_text2.hex())
    assert cipher_text1 == cipher_text2


def test_encrypt_ctr():
    key = b'sixteen-byte-key'
    msg = b'sixteen-byte-msgsixteen-byte-msgsixteen-'
    iv = b'\x12<\xcaJ\xd4\xbcE\x18\x00\x00\x00\x00\x00\x00\x00\x00'
    aes = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
    cipher_text1 = aes.encrypt(msg)

    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('CTR')
    cipher_text2 = ciph.encrypt(msg, iv)

    print('==============CTR_ENCRYPT_TEST===============')
    print("AES:    ", cipher_text1.hex())
    print("MANUAL: ", cipher_text2.hex())
    assert cipher_text1 == cipher_text2


def test_decrypt_ecb():
    key = b'sixteen-byte-key'
    msg = b'.7\t\xc299\xa4\x95\xfe&\xe8\xdbWX\x03\xdb.7\t\xc299\xa4\x95\xfe&\xe8\xdbWX\x03\xdb\x1f)&\xa7P\xda\x17\xbb\x9f\x10\xc1)]&\x03h'

    aes = AES.new(key, AES.MODE_ECB)
    cipher_text1 = aes.decrypt(msg)
    cipher_text1 = unpad(cipher_text1, BLOCK_SIZE, style='pkcs7')

    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('ECB')
    cipher_text2 = ciph.decrypt(msg, b'sixteen-byte-sad')

    print('==============ECB_DECRYPT_TEST===============')
    print("AES   : ", cipher_text1)
    print("MANUAL: ", cipher_text2)
    assert cipher_text1 == cipher_text2

def test_decrypt_cbc():
    key = b'sixteen-byte-key'
    msg = b'\x02\x98,\xda\xa3\xed\xfe\x1c-VM=\xdb\x84\t\x10\x9a\x1c\x13o\x92\x00\xdfYj\xbeH0\x9f\xd2\xe0\xa7\x1f\xfe\xef|\xfb\xbd\xf8\xca\xdc\xfe\xc7O\xd8\xd7\xf9\xe4'
    iv = b'sixteen-byte-iv-'
    aes = AES.new(key, AES.MODE_CBC, iv)
    cipher_text1 = aes.decrypt(msg)
    cipher_text1 = unpad(cipher_text1, BLOCK_SIZE, style='pkcs7')

    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('CBC')
    ciph.set_iv(iv)
    cipher_text2 = ciph.decrypt(msg, iv)

    print('==============CBC_DECRYPT_TEST===============')
    print("AES:    ", cipher_text1)
    print("MANUAL: ", cipher_text2)
    assert cipher_text1 == cipher_text2


def test_decrypt_cfb():
    key = b'sixteen-byte-key'
    msg = b'm\xf5\xf4\xed`\x85\x01\x1f\xba\xd2\xd5\xde\xfc\xacV\xc9\xd4\x10@o\xa8\x1f\x96)D^\\_W\xea\xc7&\xce#\xbeco\x83\xfa\x16'
    iv = b'sixteen-byte-iv-'
    aes = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    cipher_text1 = aes.decrypt(msg)

    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('CFB')
    ciph.set_iv(iv)
    cipher_text2 = ciph.decrypt(msg, iv)

    print('==============CFB_DECRYPT_TEST===============')
    print("AES:    ", cipher_text1)
    print("MANUAL: ", cipher_text2)
    assert cipher_text1 == cipher_text2


def test_decrypt_ofb():
    key = b'sixteen-byte-key'
    msg = b'm\xf5\xf4\xed`\x85\x01\x1f\xba\xd2\xd5\xde\xfc\xacV\xc9\xe0\x16\xb3\x90\xeb\x17\xffC\x14\x13\x7fs#\xe9EH\xc0\x12?\xab\xc1\x9b\xc6\xdf'
    iv = b'sixteen-byte-iv-'
    aes = AES.new(key, AES.MODE_OFB, iv)
    cipher_text1 = aes.encrypt(msg)

    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('OFB')
    cipher_text2 = ciph.encrypt(msg, iv)

    print('==============OFB_DECRYPT_TEST===============')
    print("AES:    ", cipher_text1)
    print("MANUAL: ", cipher_text2)
    assert cipher_text1 == cipher_text2


def test_decrypt_ctr():
    key = b'sixteen-byte-key'
    msg = b'\xbc\x88a\xc2\x04H\xef^\xacm\xe0\x0b\xfb\x15\x85u\x07\xf0r\xac\xef\x1cM\x06\xf5\xf6\x02Y\t\xeb\x8cC\x0b$\xb5\xff\x94P\x95\xdd'
    iv = b'\x12<\xcaJ\xd4\xbcE\x18\x00\x00\x00\x00\x00\x00\x00\x00'
    aes = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
    cipher_text1 = aes.decrypt(msg)

    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('CTR')
    cipher_text2 = ciph.decrypt(msg, iv)

    print('==============CTR_DECRYPT_TEST===============')
    print("AES:    ", cipher_text1)
    print("MANUAL: ", cipher_text2)
    assert cipher_text1 == cipher_text2


def task4():
    """
    Задание 4.
    Для каждого режима шифрования зашифровать и расшифровать произвольный текст длины 2,5 блока.
    """
    test_encrypt_ecb()
    test_encrypt_cbc()
    test_encrypt_cfb()
    test_encrypt_ofb()
    test_encrypt_ctr()

    test_decrypt_ecb()
    test_decrypt_cbc()
    test_decrypt_cfb()
    test_decrypt_ofb()
    test_decrypt_ctr()


task4()
