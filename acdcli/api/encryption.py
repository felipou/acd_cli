
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

import io
import logging
import os

logger = logging.getLogger(__name__)


def derive_key_and_iv(password, salt, key_length, iv_length, algo):
    d = d_i = b''
    while len(d) < key_length + iv_length:
        # d_i = md5(d_i + password + salt).digest()
        h = hashlib.new(algo)
        h.update(d_i + password.encode('utf-8') + salt)
        d_i = h.digest()

        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]


# md5, sha or sha1

AES_256_BLOCK_SIZE = 16
AES_256_KEY_SIZE = 32


def getEncryptedFileSize(file_size, block_size=AES_256_BLOCK_SIZE):
    return (
        file_size +

        # "Header" with salt
        block_size +

        # Padding
        (block_size - (file_size % block_size))
    )


class TeeBufferedEncryptionReader(object):
    """Proxy buffered reader object that allows callbacks on read
    operations."""

    def __init__(
        self, file: io.BufferedReader, callbacks: list = None,
        encryption_passphrase="",
        encryption_key_digest="sha1",
        **kwargs
    ):
        self._file = file
        self._callbacks = callbacks

        self._salt = Random.new().read(AES_256_BLOCK_SIZE - len('Salted__'))

        # print(encryption_passphrase)
        # print(encryption_key_digest)

        key, iv = derive_key_and_iv(
            encryption_passphrase, self._salt, AES_256_KEY_SIZE,
            AES_256_BLOCK_SIZE, encryption_key_digest
        )

        self._enc = AES.new(key, AES.MODE_CBC, iv)
        self._enc_tell = 0
        self._enc_ended = False

        file_size = os.fstat(self._file.fileno()).st_size

        self._enc_size = getEncryptedFileSize(file_size, AES_256_BLOCK_SIZE)

        # print(file_size, self._enc_size)

        self._buf = b''
        self._enc_buf = b'Salted__' + self._salt

    def __getattr__(self, item):
        try:
            return object.__getattr__(item)
        except AttributeError:
            # print("__getattr__", item)
            return getattr(self._file, item)

    def tell(self, *args, **kwargs):
        return self._enc_tell

    def __len__(self):
        return self._enc_size

    def __readAndEncrypt(self, ln):
        ln = max(AES_256_BLOCK_SIZE, ln)

        while len(self._buf) < ln:
            chunk_plain = self._file.read(ln-len(self._buf))
            if len(chunk_plain) == 0:
                # print("data ended", ln, len(self._buf))
                break
            self._buf += chunk_plain

        buf_cut_index = max(
            int(len(self._buf)/AES_256_BLOCK_SIZE)*AES_256_BLOCK_SIZE,
            AES_256_BLOCK_SIZE
        )
        buf_chunk = self._buf[:buf_cut_index]
        self._buf = self._buf[buf_cut_index:]

        if len(buf_chunk) < AES_256_BLOCK_SIZE and not self._enc_ended:
            pad_length = (AES_256_BLOCK_SIZE - len(buf_chunk))
            buf_chunk += pad_length * bytes([pad_length])
            self._enc_ended = True

        # print('buf_chunk sizes:', len(buf_chunk), ln)

        if len(buf_chunk) > 0:
            chunk = self._enc.encrypt(buf_chunk)
        else:
            chunk = buf_chunk

        # print('chunk sizes:', len(chunk), len(buf_chunk), ln)

        return chunk

    def read(self, ln=-1):
        # ln = ln if ln in (0, -1) else FS_RW_CHUNK_SZ

        if len(self._enc_buf) < ln:
            self._enc_buf += self.__readAndEncrypt(ln-len(self._enc_buf))

        chunk = self._enc_buf[:ln]
        self._enc_buf = self._enc_buf[ln:]

        self._enc_tell += len(chunk)

        # print('enc chunk:', len(chunk), ln)

        for callback in self._callbacks or []:
            callback(chunk)
        return chunk


class BufferedDecryptionWriter(object):
    def __init__(
        self,
        file,
        decryption_passphrase="",
        decryption_key_digest="sha1",
        file_size=0,
        **kwargs
    ):
        self._file = file
        self._tell_pos = 0
        self._salt = None
        self._data_buf = b''
        self._file_size = file_size

        self._decrypted_tell_pos = 0

        self._passphrase = decryption_passphrase
        self._key_digest = decryption_key_digest

    def tell(self):
        return self._tell_pos

    def __cutData(self, index):
        data = self._data_buf[:index]
        self._data_buf = self._data_buf[index:]
        return data

    def __initEnc(self):
        key, iv = derive_key_and_iv(
            self._passphrase, self._salt, AES_256_KEY_SIZE,
            AES_256_BLOCK_SIZE, self._key_digest
        )

        self._enc = AES.new(key, AES.MODE_CBC, iv)

    def __decryptAndWrite(self):
        if self._salt is None:
            if len(self._data_buf) < AES_256_BLOCK_SIZE:
                return

            salt_str = self.__cutData(AES_256_BLOCK_SIZE)

            self._salt = salt_str[len("Salted__"):]
            self.__initEnc()

        if len(self._data_buf) < 2*AES_256_BLOCK_SIZE:
            return

        blocks_available = int(len(self._data_buf)/AES_256_BLOCK_SIZE)
        cut_index = (blocks_available-1)*AES_256_BLOCK_SIZE

        data = self.__cutData(cut_index)
        data = self._enc.decrypt(data)

        self._decrypted_tell_pos += len(data)
        self._file.write(data)

    def write(self, chunk):
        self._data_buf += chunk
        self._tell_pos += len(chunk)
        self.__decryptAndWrite()

    def flush(self):
        self._file.flush()

    def close(self):
        data = self._enc.decrypt(self._data_buf)
        self._data_buf = b''

        padding_size = data[-1]
        padding = padding_size * bytes([padding_size])

        if not data.endswith(padding):
            raise Exception("invalid padding")

        data = data[:-padding_size]

        self._decrypted_tell_pos += len(data)
        self._file.write(data)

        if (
            self._file_size > 0 and
            self._file_size !=
            self._decrypted_tell_pos + padding_size + AES_256_BLOCK_SIZE
        ):
            raise Exception("invalid file size")

        return self._decrypted_tell_pos
