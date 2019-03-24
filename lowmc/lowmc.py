"""The LowMC blockcipher in Python."""

from BitVector import BitVector
import os
from typing import Optional

__author__ = "Thorsten Knoll"
__copyright__ = "Thorsten Knoll"
__license__ = "mit"


class LowMC(object):
    """LowMC blockcipher mainclass.

    For de- and encryption of message blocks with the LowMC blockipher.
    This class can handle the various Picnic security levels and is able to
    generate or set and store a single privat key.
    """

    __slots__ = ['__blocksize', '__keysize', '__number_sboxes',
                 '__number_rounds', '__filename', '__blocksize_bytes',
                 '__keysize_bytes', '__plaintext', '__priv_key', '__state',
                 '__lin_layer', '__lin_layer_inv', '__round_consts',
                 '__round_key_mats', '__sbox', '__sbox_inv']

    def __init__(self, param: str) -> None:
        """Instanciates a LowMC object.

        Args:
            param:  A string containing the Picnic security level
        """
        if (param == 'picnic-L1'):
            self.__blocksize = 128
            self.__keysize = 128
            self.__number_sboxes = 10
            self.__number_rounds = 20
            self.__filename = 'picnic-L1.dat'
        elif (param == 'picnic-L3'):
            self.__blocksize = 192
            self.__keysize = 192
            self.__number_sboxes = 10
            self.__number_rounds = 30
            self.__filename = 'picnic-L3.dat'
        elif (param == 'picnic-L5'):
            self.__blocksize = 256
            self.__keysize = 256
            self.__number_sboxes = 10
            self.__number_rounds = 38
            self.__filename = 'picnic-L5.dat'
        else:
            raise Exception('Argument is not a valid Picnic security Level: {}'
                            .format(param))

        self.__blocksize_bytes = int(self.__blocksize / 8)
        self.__keysize_bytes = int(self.__keysize / 8)

        self.__plaintext = None

        self.__priv_key = None
        self.__state = None
        self.__lin_layer = []
        self.__lin_layer_inv = []
        self.__round_consts = []
        self.__round_key_mats = []
        self.__sbox = [0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02]
        self.__sbox_inv = [0x00, 0x01, 0x07, 0x02, 0x05, 0x06, 0x03, 0x04]

        self.__read_constants()
        self.__invert_lin_matrix()

    @property
    def private_key(self) -> bytes:
        """Private key getter.

        Getter method for returning the private key

        Returns:
            bytearray of the private key

        """
        return self.__priv_key

    @private_key.setter
    def private_key(self, priv_key: Optional[bytes] = None) -> None:
        """Set or generate a private key.

        If no private key is provided as argument, one is generated from the
        CSPRNG of the underlying OS. This should be a plattform independend
        source for randomness. It will have the length self.__keysize_bytes.

        Args:
            priv_key:   If provided, must be a bytearray of
                        length self.__keysize_bytes
        """
        if (priv_key is None):
            temp_key = os.urandom(int(self.__keysize_bytes))
            self.__priv_key = BitVector(rawbytes=temp_key)
        else:
            assert (len(priv_key) == self.__keysize_bytes), \
                    "Private key has length != keysize"
            self.__priv_key = BitVector(rawbytes=priv_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encryption of a plaintext.

        Args:
            plaintext:  Must be a bytearray of length self.__blocksize_bytes

        Returns:
            A bytearray containing the ciphertext of
            length self.__blocksize_bytes

        """
        assert (len(plaintext) == self.__blocksize_bytes), \
            "Plaintext has length != blocksize"
        assert (self.__priv_key is not None), "Private key not set"

        self.__state = BitVector(rawbytes=plaintext)

        self.__key_addition(0)

        for i in range(self.__number_rounds):
            self.__apply_sbox()
            self.__multiply_with_lin_mat(i)
            self.__state = self.__state ^ self.__round_consts[i]
            self.__key_addition(i + 1)

        result = bytes.fromhex(self.__state.get_bitvector_in_hex())
        self.__state = None
        return result

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decryption of a ciphertext.

        Args:
            ciphertext:  Must be a bytearray of length self.__blocksize_bytes

        Returns:
            bytearray containing the plaintext of length self.__blocksize_bytes

        """
        assert (len(ciphertext) == self.__blocksize_bytes), \
            "Ciphertext has length != blocksize"
        assert (self.__priv_key is not None), "Private key not set"

        self.__state = BitVector(rawbytes=ciphertext)

        for i in range(self.__number_rounds, 0, -1):
            self.__key_addition(i)
            self.__state = self.__state ^ self.__round_consts[i - 1]
            self.__multiply_with_lin_mat_inv(i - 1)
            self.__apply_sbox_inv()

        self.__key_addition(0)

        result = bytes.fromhex(self.__state.get_bitvector_in_hex())
        self.__state = None
        return result

    def __apply_sbox(self) -> None:
        result = BitVector(size=self.__blocksize)
        state_copy = self.__state.deep_copy()

        # Copy the identity part of the message
        result_ident = state_copy[(3 * self.__number_sboxes):self.__blocksize]

        # Substitute the rest of the message with the sboxes
        # ----------------------------------------------------
        # ATTENTION: The 3-bit chunks seem to be reversed
        # in the Picnic-Ref-Implementation, compared to the
        # LowMC-Ref-Implementation and the original LowMC-paper.
        # Example: state[0:3]='001' becomes '100' then gets sboxed
        # to '111' and reversed again for the state-update.
        # ----------------------------------------------------
        state_copy = self.__state[0:(3 * self.__number_sboxes)]
        result_sbox = BitVector(size=0)
        for i in range(self.__number_sboxes):
            state_index = (3 * i)
            state_3_bits = state_copy[state_index:state_index + 3].reverse()
            sbox_3_bits = BitVector(intVal=self.__sbox[int(state_3_bits)],
                                    size=3).reverse()
            result_sbox = result_sbox + sbox_3_bits

        result = result_sbox + result_ident
        self.__state = result

    def __apply_sbox_inv(self) -> None:
        result = BitVector(size=self.__blocksize)
        state_copy = self.__state.deep_copy()

        # Copy the identity part of the message
        result_ident = state_copy[(3 * self.__number_sboxes):self.__blocksize]

        # Substitute the rest of the message with the inverse sboxes
        # ----------------------------------------------------
        # ATTENTION: The 3-bit chunks seem to be reversed
        # in the Picnic-Ref-Implementation, compared to the
        # LowMC-Ref-Implementation and the original LowMC-paper.
        # ----------------------------------------------------
        state_copy = self.__state[0:(3 * self.__number_sboxes)]
        result_sbox = BitVector(size=0)
        for i in range(self.__number_sboxes):
            state_index = (3 * i)
            state_3_bits = state_copy[state_index:state_index + 3].reverse()
            sbox_3_bits = BitVector(intVal=self.__sbox_inv[int(state_3_bits)],
                                    size=3).reverse()
            result_sbox = result_sbox + sbox_3_bits

        result = result_sbox + result_ident
        self.__state = result

    def __multiply_with_lin_mat(self, r: int) -> None:
        result = BitVector(size=self.__blocksize)
        for i in range(self.__blocksize):
            result[i] = (self.__lin_layer[r][i] & self.__state) \
                .count_bits() % 2
        self.__state = result

    def __multiply_with_lin_mat_inv(self, r: int) -> None:
        result = BitVector(size=self.__blocksize)
        for i in range(self.__blocksize):
            result[i] = (self.__lin_layer_inv[r][i] & self.__state) \
                        .count_bits() % 2
        self.__state = result

    def __key_addition(self, r: int) -> None:
        round_key = BitVector(size=self.__keysize)
        for i in range(self.__blocksize):
            round_key[i] = (self.__round_key_mats[r][i] & self.__priv_key) \
                            .count_bits() % 2
        self.__state = self.__state ^ round_key

    def __read_constants(self) -> None:
        with open(self.__filename, 'r') as matfile:
            const_data = matfile.read()

        const_data_split = const_data.split('\n')

        # Check for correct parameters and file length
        params = const_data_split[0:3]
        assert params[0] == str(self.__blocksize), \
            "Wrong blocksize in data file!"
        assert params[1] == str(self.__keysize), \
            "Wrong keysize in data file!"
        assert params[2] == str(self.__number_rounds), \
            "Wrong number of rounds in data file!"
        assert (len(const_data_split) - 1) == 3 \
            + (((self.__number_rounds * 2) + 1) * self.__blocksize) \
            + self.__number_rounds, \
            "Wrong file size (number of lines)"

        # Linear layer matrices
        lines_offset = 3
        lines_count = self.__number_rounds * self.__blocksize
        lin_layer = const_data_split[lines_offset:(lines_offset + lines_count)]
        for r in range(self.__number_rounds):
            mat = []
            for s in range(self.__blocksize):
                bv = BitVector(bitstring=lin_layer[(r * self.__blocksize) + s])
                mat.append(bv)
            self.__lin_layer.append(mat)

        # Round constants
        lines_offset += lines_count
        lines_count = self.__number_rounds
        round_consts = const_data_split[lines_offset:(lines_offset
                                        + lines_count)]
        for line in round_consts:
            self.__round_consts.append(BitVector(bitstring=line))

        # Round key matrices
        lines_offset += lines_count
        lines_count = (self.__number_rounds + 1) * self.__blocksize
        round_key_mats = const_data_split[lines_offset:(lines_offset
                                          + lines_count)]
        for r in range(self.__number_rounds + 1):
            mat = []
            for s in range(self.__blocksize):
                mat.append(BitVector(
                    bitstring=round_key_mats[(r * self.__blocksize) + s]))
            self.__round_key_mats.append(mat)

    def __invert_lin_matrix(self) -> None:

        self.__lin_layer_inv = []
        for r in range(self.__number_rounds):

            # Copy lin_layer
            mat = []
            for i in range(self.__blocksize):
                mat.append(self.__lin_layer[r][i].deep_copy())

            # Create (initial identity) matrix, where the
            # inverted matrix will be stored in.
            inv_mat = []
            for i in range(self.__blocksize):
                temp_bv = BitVector(intVal=0, size=self.__blocksize)
                temp_bv[i] = 1
                inv_mat.append(temp_bv)

            # Transform to upper triangular matrix
            row = 0
            for col in range(self.__keysize):
                if (not mat[row][col]):
                    r = row + 1
                    while ((r < self.__blocksize) and (not mat[r][col])):
                        r += 1
                    if (r >= self.__blocksize):
                        continue
                    else:
                        temp = mat[row]
                        mat[row] = mat[r]
                        mat[r] = temp
                        temp = inv_mat[row]
                        inv_mat[row] = inv_mat[r]
                        inv_mat[r] = temp
                for i in range(row + 1, self.__blocksize):
                    if (mat[i][col]):
                        mat[i] = mat[i] ^ mat[row]
                        inv_mat[i] = inv_mat[i] ^ inv_mat[row]
                row += 1

            # Transform to inverse matrix
            for col in range(self.__keysize, 0, -1):
                for r in range(col - 1):
                    if (mat[r][col - 1]):
                        mat[r] = mat[r] ^ mat[col - 1]
                        inv_mat[r] = inv_mat[r] ^ inv_mat[col - 1]

            self.__lin_layer_inv.append(inv_mat)
