import binascii

from Crypto.Cipher import AES
import os
from struct import pack
from Crypto.Util.Padding import pad, unpad


BLOCK_SIZE = 16
IV_SIZE = BLOCK_SIZE


class Cipher:
    def __init__(self):
        self.key = None
        self.mode = None
        self.aes_object = None
        self.iv = None

    def set_key(self, key):
        """
        Установка ключа шифрования (расшифрования)
        :param key: байтовое представление ключа блочного шифра
        :type key: bytes
        """
        if key is None:
            raise ValueError("Ключ должен быть инициализирован")

        if not isinstance(key, bytes):
            raise ValueError("Ключ должна иметь тип bytes")

        if len(key) == 0:
            raise ValueError("Длина ключа должна быть больше нуля")

        self.key = key
        self.aes_object = AES.new(self.key, AES.MODE_ECB)

    def set_mode(self, mode):
        """
        Указание режима шифрования
        :param mode: режим шифрования, допустимые значения ECB, CBC, CFB, OFB, CTR.
        :type mode: str
        :raises ValueError: Если указан недопустимый режим шифрования.
        """
        if mode in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
            self.mode = mode
        else:
            raise ValueError('Допустимые значения режима шифрования: ECB, CBC, CFB, OFB, CTR')

    def set_iv(self, iv):
        """
        Установка вектора инициализации
        :param iv: вектор инициализации
        :type iv: bytes
        """
        if len(iv) != IV_SIZE:
            raise ValueError(f"iv должен быть длиной в {IV_SIZE} байт")
        self.iv = iv

    def encrypt(self, data, iv=None):
        """
        Функция зашифрования на заданном ключе
        :param data: массив байт для шифрования
        :type data: bytes
        :param iv: вектор инициализации или начальное заполнение счётчика в указанном режиме
        :type iv: bytes
        :return: расшифрованная байтовая строка
        :rtype: bytes
        """

        if data is None:
            raise ValueError("Переменная data должна быть инициализирована")

        if not isinstance(data, bytes):
            raise ValueError("Переменная data должна иметь тип bytes")

        if len(data) == 0:
            raise ValueError("Данные для шифрования отсутствуют")

        if self.mode is None:
            raise ValueError("Переменная mode должна быть инициализирована")

        if iv is not None:
            self.set_iv(iv)

        blocks = [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
        block_count = len(blocks)
        result = b''

        for i in range(block_count):
            is_final_block = True if (i == block_count - 1) else False
            result += self.process_block_encrypt(blocks[i], is_final_block)
        return result

    def process_block_encrypt(self, plain_text, is_final_block):
        """
        Функция добавления блока открытого текста для зашифрования, содержит вызов функции BlockCipherEncrypt.
        В рамках данной функции должна быть реализована логика всех режимов, т.е. ветвление по режимам происходит тут.
        :param plain_text: Блок для шифрования
        :type plain_text: bytes
        :param is_final_block: флаг того, что передан последний блок шифруемого открытого текста
        :type is_final_block: bool
        :return: возвращает зашифрованный блок данных.
        :rtype: bytes
        """

        if self.mode == 'ECB':
            if is_final_block:
                padded_data = Cipher.pad(plain_text)
                if len(padded_data) == BLOCK_SIZE * 2:
                    enc_block1 = self.block_cipher_encrypt(padded_data[:BLOCK_SIZE])
                    enc_block2 = self.block_cipher_encrypt(padded_data[BLOCK_SIZE:])
                    return enc_block1 + enc_block2
                else:
                    cipher_text = self.block_cipher_encrypt(padded_data)
                    return cipher_text
            else:
                cipher_text = self.block_cipher_encrypt(plain_text)
            return cipher_text

        elif self.mode == 'CBC':
            if is_final_block:
                padded_data = self.pad(plain_text)
                if len(padded_data) == BLOCK_SIZE * 2:
                    enc_block1 = padded_data[:BLOCK_SIZE]
                    enc_block1_iv = self.xor_bytes(enc_block1, self.iv)
                    cipher_text1 = self.block_cipher_encrypt(enc_block1_iv)

                    self.iv = cipher_text1
                    enc_block2 = padded_data[BLOCK_SIZE:]
                    enc_block2_iv = self.xor_bytes(enc_block2, self.iv)
                    cipher_text2 = self.block_cipher_encrypt(enc_block2_iv)
                    return cipher_text1 + cipher_text2
                else:
                    enc_block_iv = self.xor_bytes(padded_data, self.iv)
                    return self.block_cipher_encrypt(enc_block_iv)

            else:
                data_iv = self.xor_bytes(plain_text, self.iv)
                cipher_text = self.block_cipher_encrypt(data_iv)
                self.iv = cipher_text
                return cipher_text

        elif self.mode == 'CFB':
            encrypted_iv = self.block_cipher_encrypt(self.iv)
            cipher_text = self.xor_bytes(plain_text, encrypted_iv[:len(plain_text)])
            self.iv = cipher_text
            return cipher_text

        elif self.mode == 'OFB':
            encrypted_iv = self.block_cipher_encrypt(self.iv)
            cipher_text = self.xor_bytes(plain_text, encrypted_iv[:len(plain_text)])
            self.iv = encrypted_iv
            return cipher_text

        elif self.mode == 'CTR':
            encrypted_iv = self.block_cipher_encrypt(self.iv)
            cipher_text = self.xor_bytes(plain_text, encrypted_iv[:len(plain_text)])
            self.iv = Cipher.increment_last_bytes(self.iv)
            return cipher_text

        else:
            raise ValueError(f"Переменная mode содержит недопустимое значение {self.mode}.\n"
                             "Допустимые значения: ECB, CBC, CFB, OFB, CTR")

    def block_cipher_encrypt(self, plain_text):
        """
        Функция шифрования блока данных алгоритмом AES
        :param plain_text: блок для шифрования BLOCK_SIZE байт
        :type plain_text: bytes
        :return: возвращает зашифрованный блок данных. BLOCK_SIZE байт
        :return: возвращает зашифрованный блок данных. BLOCK_SIZE байт
        :rtype: bytes
        """
        if len(plain_text) != BLOCK_SIZE:
            raise ValueError(f"Block size must be exactly {BLOCK_SIZE} bytes")
        cipher_text = self.aes_object.encrypt(plain_text)
        return cipher_text

    def decrypt(self, cipher_text, iv=None):
        """
        Функция расшифрования на заданном ключе
        :param cipher_text: массив байт для расшифрования
        :type cipher_text: bytes
        :param iv: вектор инициализации или начальное заполнение счётчика в указанном режиме
        :type iv: bytes
        :return: расшифрованная байтовая строка
        :rtype: bytes
        """
        if cipher_text is None:
            raise ValueError("Переменная cipher_text должна быть инициализирована")

        if not isinstance(cipher_text, bytes):
            raise ValueError("Переменная cipher_text должна иметь тип bytes")

        if len(cipher_text) == 0:
            raise ValueError("Данные для расшифрования отсутствуют")

        if self.mode is None:
            raise ValueError("Переменная mode должна быть инициализирована")

        if self.mode not in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
            raise ValueError('Допустимые значения режима шифрования: ECB, CBC, CFB, OFB, CTR')

        if iv is not None:
            self.set_iv(iv)

        self.set_iv(iv)
        blocks = [cipher_text[i:i + BLOCK_SIZE] for i in range(0, len(cipher_text), BLOCK_SIZE)]
        block_count = len(blocks)
        result = b''

        for i in range(block_count):
            is_final_block = True if (i == block_count - 1) else False
            result += self.process_block_decrypt(blocks[i], is_final_block)
        return result

    def process_block_decrypt(self, cipher_text, is_final_block):
        """
        Функция добавления блока зашифрвоанного текста для расшифрования,
        содержит вызов функции block_cipher_encrypt и block_cipher_decrypt.
        В рамках данной функции должна быть реализована логика всех режимов, т.е. ветвление по режимам происходит тут.
        :param cipher_text: Блок для расшифрования
        :type cipher_text: bytes
        :param is_final_block: флаг того, что передан последний блок шифруемого открытого текста
        :type is_final_block: bool
        :return: возвращает зашифрованный блок данных.
        :rtype: bytes
        """
        if self.mode == 'ECB':
            plain_text = self.block_cipher_decrypt(cipher_text)
            if is_final_block:
                plain_text = self.unpad(plain_text)
            return plain_text

        elif self.mode == 'CBC':
            decryption_block = self.block_cipher_decrypt(cipher_text)
            plain_text = self.xor_bytes(decryption_block, self.iv)
            self.iv = cipher_text
            if is_final_block:
                plain_text = self.unpad(plain_text)
            return plain_text

        elif self.mode == 'CFB':
            decryption_block = self.block_cipher_encrypt(self.iv)
            plain_text = self.xor_bytes(decryption_block[:len(cipher_text)], cipher_text)
            self.iv = cipher_text
            return plain_text

        elif self.mode == 'OFB':
            decryption_block = self.block_cipher_encrypt(self.iv)
            plain_text = self.xor_bytes(decryption_block, cipher_text)
            self.iv = decryption_block
            return plain_text

        elif self.mode == 'CTR':
            encrypted_iv = self.block_cipher_encrypt(self.iv)
            plain_text = self.xor_bytes(cipher_text, encrypted_iv[:len(cipher_text)])
            self.iv = Cipher.increment_last_bytes(self.iv)
            return plain_text

        else:
            raise ValueError(f"Переменная mode содержит недопустимое значение {self.mode}.\n"
                             "Допустимые значения: ECB, CBC, CFB, OFB, CTR")

    def block_cipher_decrypt(self, cypher_text):
        """
        Функция расшифрования блока данных алгоритмом AES
        :param cypher_text: блок для расшифрования BLOCK_SIZE байт
        :type cypher_text: bytes
        :return: возвращает расшифрованный блок данных. BLOCK_SIZE байт
        :rtype: bytes
        """
        if len(cypher_text) != BLOCK_SIZE:
            raise ValueError(f"Block size must be exactly {BLOCK_SIZE} bytes")
        plain_text = self.aes_object.decrypt(cypher_text)
        return plain_text

    @staticmethod
    def pad(data):  # pkcs7_pad
        length = len(data)
        remainder = length % BLOCK_SIZE
        number = BLOCK_SIZE - remainder
        barray = bytes([number] * number)
        return data + barray

    @staticmethod
    def unpad(padded_data):
        """
        Удаление PKCS#7 паддинга из данных
        :param padded_data: данные с добавленным паддингом
        :type padded_data: bytes
        :return: данные без паддинга
        :rtype: bytes
        :raises ValueError: Если длина паддинга меньше единицы или больше BLOCK_SIZE. Или байты паддинга не совпадают.
        """
        padding_len = padded_data[-1]
        if padding_len < 1 or padding_len > BLOCK_SIZE:
            raise ValueError("Некорректное значение паддинга")
        for byte in padded_data[-padding_len:]:
            if byte != padding_len:
                raise ValueError("Некорректные байты паддинга")
        return padded_data[:-padding_len]

    @staticmethod
    def xor_bytes(bytes1, bytes2):
        """
        Выполняет операцию XOR между двумя байтовыми строками одинаковой длины.
        :param bytes1: Первая байтовая строка
        :type bytes1: bytes
        :param bytes2: Вторая байтовая строка, должна быть той же длины, что и первая.
        :type bytes2: bytes
        :return: Результат операции XOR в виде байтовой строки.
        :rtype: bytes
        :raises ValueError: Если длины входных байтовых строк не совпадают.
        """
        if len(bytes1) != len(bytes2):
            raise ValueError("Байтовые строки должны иметь одинаковую длину")
        return bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))

    @staticmethod
    def generate_iv():
        return os.urandom(BLOCK_SIZE)

    @staticmethod
    def generate_iv_with_nonce():
        """
        Генерирует вектор инициализации (IV).
        :return: Сгенерированный IV, который является комбинацией (BLOCK_SIZE//2)-байтового nonce и (BLOCK_SIZE//2)-байтового счетчика.
        :rtype: bytes
        """
        nonce = os.urandom(BLOCK_SIZE//2)
        counter = 0
        nonce_counter = nonce + pack('>Q', counter)
        return nonce_counter

    @staticmethod
    def increment_last_bytes(byte_string):
        """
        Увеличивает значение последние BLOCK_SIZE//2 байтов байтовой строки на 1.
        :param byte_string: Байтовая строка.
        :type byte_string: bytes
        :return: Новая байтовая строка с инкрементированными последними BLOCK_SIZE//2 байтами.
        :rtype: bytes
        """
        # Извлекаем последние (BLOCK_SIZE//2) байтов как числа
        counter = int.from_bytes(byte_string[-BLOCK_SIZE//2:], byteorder='big')
        counter += 1
        # Преобразуем числа обратно в байты
        counter_bytes = counter.to_bytes(BLOCK_SIZE//2, byteorder='big')
        new_byte_string = byte_string[:-BLOCK_SIZE//2] + counter_bytes
        return new_byte_string


def task25():
    """
    Задание 2.5
    Использование реализации режима CBC для валидации вашей реализации режима CBC.
    """

    key = b'sixteen-byte-key'
    msg = b'sixteen-byte-msgsixteen-byte-msgsixteen-'
    iv = b'sixteen-byte-iv-'

    # Задаем параметры
    ciph = Cipher()
    ciph.set_key(key)
    ciph.set_mode('CBC')
    ciph.set_iv(iv)

    # 1) Шифруем сообщение с помощью моей реализации CBC
    cipher_msg = ciph.encrypt(msg, iv)
    # 2) Расшифровываем сообщение с помощью библиотечной реализации CBC
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plain_text = aes.decrypt(cipher_msg)
    plain_text = unpad(padded_plain_text, BLOCK_SIZE, style='pkcs7')

    # сравниваем исходное сообщение с расшифрованным
    assert msg == plain_text

    # 3) Шифруем сообщение с помощью библиотечной реализации CBC
    pad_msg = pad(msg, BLOCK_SIZE, style='pkcs7')
    aes = AES.new(key, AES.MODE_CBC, iv) # тут придётся создать новый объект, иначе не работает
    cipher_text = aes.encrypt(pad_msg)

    # 4) Расшифровываем сообщение с помощью моей реализации CBC
    plain_text = ciph.decrypt(cipher_text, iv)

    # сравниваем исходное сообщение с расшифрованным
    assert msg == plain_text


def task3():
    """
    Задание 3
    Расшифровать следующие шифртексты
    CBC key: 140b41b22a29beb4061bda66b6747e14
    CBC Ciphertext 1: 4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81

    CBC key: 140b41b22a29beb4061bda66b6747e14
    CBC Ciphertext 2: 5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253

    CTR key: 36f18357be4dbd77f050515c73fcf9f2
    CTR Ciphertext 1: 69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329

    CTR key: 36f18357be4dbd77f050515c73fcf9f2
    CTR Ciphertext 2: 770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451
    """
    cipher = Cipher()
    cipher.set_mode('CBC')
    key = binascii.unhexlify('140b41b22a29beb4061bda66b6747e14')
    msg_hex = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'
    msg = binascii.unhexlify(msg_hex)
    iv = msg[:16]
    cipher_text = msg[16:]
    cipher.set_key(key)
    plain_text = cipher.decrypt(cipher_text, iv)
    print(plain_text) # b'Basic CBC mode encryption needs padding.'

    cipher.set_mode('CBC')
    key = binascii.unhexlify('140b41b22a29beb4061bda66b6747e14')
    msg_hex = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'
    msg = binascii.unhexlify(msg_hex)
    iv = msg[:16]
    cipher_text = msg[16:]
    cipher.set_key(key)
    plain_text = cipher.decrypt(cipher_text, iv)
    print(plain_text) # b'Our implementation uses rand. IV'

    cipher.set_mode('CTR')
    key = binascii.unhexlify('36f18357be4dbd77f050515c73fcf9f2')
    msg_hex = '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'
    msg = binascii.unhexlify(msg_hex)
    iv = msg[:16]
    cipher_text = msg[16:]
    cipher.set_key(key)
    plain_text = cipher.decrypt(cipher_text, iv)
    print(plain_text) # b'CTR mode lets you build a stream cipher from a block cipher.'

    cipher.set_mode('CTR')
    key = binascii.unhexlify('36f18357be4dbd77f050515c73fcf9f2')
    msg_hex = '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'
    msg = binascii.unhexlify(msg_hex)
    iv = msg[:16]
    cipher_text = msg[16:]
    cipher.set_key(key)
    plain_text = cipher.decrypt(cipher_text, iv)
    print(plain_text) # b'Always avoid the two time pad!'


task25()
task3()
