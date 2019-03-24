'''
---------------------------------------------------
LowMC Blockcipher in Python
Author: Thorsten Knoll
Date: Feb 2019

This implementation walks along the
C and C++ reference implementations for
LowMC and Picnic in these GitHubs:
https://github.com/LowMC/lowm
https://github.com/Microsoft/Picnic

The function __invert_lin_matrix()
is a plain transcript to python from 
the LowMC C++ ref-implementation

LowMC, Picnic and this file are published 
under MIT Licence. See the LICENCE.md file.
---------------------------------------------------
'''

import os
from BitVector import BitVector

class LowMC:

  __slots__ = ['blocksize', 'keysize', 'number_sboxes', 'number_rounds', 'filename', 'plaintext',
               '__priv_key', '__state', '__lin_layer', '__lin_layer_inv', '__round_consts',
               '__round_key_mats', '__sbox', '__sbox_inv']

  def __init__(self, param):

    print("LowMC init for " + param)

    # Set security parameters according to param
    if (param == 'picnic-L1'):
      self.blocksize = 128
      self.keysize   = 128
      self.number_sboxes = 10
      self.number_rounds = 20
      self.filename  = 'picnic-L1.dat'
    elif (param == 'picnic-L3'):
      self.blocksize = 192
      self.keysize   = 192
      self.number_sboxes = 10
      self.number_rounds = 30
      self.filename  = 'picnic-L3.dat'
    elif (param == 'picnic-L5'):
      self.blocksize = 256
      self.keysize   = 256
      self.number_sboxes = 10
      self.number_rounds = 38
      self.filename  = 'picnic-L5.dat'

    # Public variables
    self.plaintext = None

    # Private variables
    self.__priv_key = None
    self.__state = None
    self.__lin_layer = []
    self.__lin_layer_inv = []
    self.__round_consts = []
    self.__round_key_mats = []
    self.__sbox = [ 0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02 ]
    self.__sbox_inv = [ 0x00, 0x01, 0x07, 0x02, 0x05, 0x06, 0x03, 0x04 ]
  
    # Call init functions
    self.__read_constants()
    self.__invert_lin_matrix()
    
    print("LowMC init done")

  '''
  ////////////////////////////
  ///   Public functions   ///
  ////////////////////////////
  '''
  # Generate private key with lenght self.keysize from urandom
  def generate_priv_key(self) :
    temp_key = os.urandom(int(self.keysize / 8))
    self.__priv_key = BitVector(rawbytes = temp_key)

  # Set private key
  # @param priv_key as raw bytes with length self.keysize
  def set_priv_key(self, priv_key):
    assert (len(priv_key) * 8 == self.keysize), "Private key has length != keysize"
    self.__priv_key = BitVector(rawbytes = priv_key)

  # Encrypts a plaintext
  # @param plaintext must be raw bytes with length blocksize
  # @return ciphertext as raw bytes with length blocksize
  def encrypt(self, plaintext):
    assert (len(plaintext) * 8) == self.blocksize, "Plaintext has length != blocksize"
    assert (self.__priv_key is not None), "Private key not set"

    self.__state = BitVector(rawbytes = plaintext)

    self.__key_addition(0)

    for i in range(self.number_rounds):
      self.__apply_sbox()
      self.__multiply_with_lin_mat(i)
      self.__state = self.__state ^ self.__round_consts[i]
      self.__key_addition(i + 1)

    result = bytes.fromhex(self.__state.get_bitvector_in_hex())
    self.__state = None
    return result

  # Decrypts a ciphertext
  # @param ciphertext must be raw bytes with length blocksize
  # @return plaintext as raw bytes with length blocksize
  def decrypt(self, ciphertext):
    assert (len(ciphertext) * 8) == self.blocksize, "Ciphertext has length != blocksize"
    assert (self.__priv_key is not None), "Private key not set"

    self.__state = BitVector(rawbytes = ciphertext)

    for i in range(self.number_rounds, 0, -1):
      self.__key_addition(i)
      self.__state = self.__state ^ self.__round_consts[i - 1]
      self.__multiply_with_lin_mat_inv(i - 1)
      self.__apply_sbox_inv()

    self.__key_addition(0)

    result = bytes.fromhex(self.__state.get_bitvector_in_hex())
    self.__state = None
    return result

  '''
  /////////////////////////////
  ///   Priavte functions   ///
  /////////////////////////////
  '''
  def __apply_sbox(self):
    result = BitVector(size = self.blocksize)
    state_copy = self.__state.deep_copy()

    # Copy the identity part of the message
    result_ident = state_copy[(3 * self.number_sboxes):self.blocksize]

    # Substitute the rest of the message with the sboxes
    # ----------------------------------------------------
    # ATTENTION: The 3-bit chunks seem to be reversed 
    # in the Picnic-Ref-Implementation, compared to the
    # LowMC-Ref-Implementation and the original LowMC-paper.
    # Example: state[0:3]='001' becomes '100' then gets sboxed 
    # to '111' and reversed again for the state-update.
    # ----------------------------------------------------
    state_copy = self.__state[0:(3 * self.number_sboxes)]
    result_sbox = BitVector(size = 0)
    for i in range(self.number_sboxes):
      state_index = (3 * i)
      state_3_bits = state_copy[state_index:state_index + 3].reverse()
      sbox_3_bits = BitVector(intVal = self.__sbox[int(state_3_bits)], size = 3).reverse()
      result_sbox = result_sbox + sbox_3_bits

    result = result_sbox + result_ident
    self.__state = result

  def __apply_sbox_inv(self):
    result = BitVector(size = self.blocksize)
    state_copy = self.__state.deep_copy()

    # Copy the identity part of the message
    result_ident = state_copy[(3 * self.number_sboxes):self.blocksize]

    # Substitute the rest of the message with the inverse sboxes
    # ----------------------------------------------------
    # ATTENTION: The 3-bit chunks seem to be reversed 
    # in the Picnic-Ref-Implementation, compared to the
    # LowMC-Ref-Implementation and the original LowMC-paper.
    # ----------------------------------------------------
    state_copy = self.__state[0:(3 * self.number_sboxes)]
    result_sbox = BitVector(size = 0)
    for i in range(self.number_sboxes):
      state_index = (3 * i)
      state_3_bits = state_copy[state_index:state_index + 3].reverse()
      sbox_3_bits = BitVector(intVal = self.__sbox_inv[int(state_3_bits)], size = 3).reverse()
      result_sbox = result_sbox + sbox_3_bits

    result = result_sbox + result_ident
    self.__state = result

  def __multiply_with_lin_mat(self, r):
    result = BitVector(size = self.blocksize)
    for i in range(self.blocksize):
      result[i] = (self.__lin_layer[r][i] & self.__state).count_bits() % 2
    self.__state = result
    
  def __multiply_with_lin_mat_inv(self, r):
    result = BitVector(size = self.blocksize)
    for i in range(self.blocksize):
      result[i] = (self.__lin_layer_inv[r][i] & self.__state).count_bits() % 2
    self.__state = result

  def __key_addition(self, r):
    round_key = BitVector(size = self.keysize)
    for i in range(self.blocksize):
      round_key[i] = (self.__round_key_mats[r][i] & self.__priv_key).count_bits() % 2
    self.__state = self.__state ^ round_key

  def __read_constants(self):
    with open(self.filename, 'r') as matfile:
      const_data = matfile.read()

    const_data_split = const_data.split('\n')

    # Check for correct parameters and file length
    params = const_data_split[0:3]
    assert params[0] == str(self.blocksize), "Wrong blocksize in data file!"
    assert params[1] == str(self.keysize), "Wrong keysize in data file!"
    assert params[2] == str(self.number_rounds), "Wrong number of rounds in data file!"
    assert (len(const_data_split) - 1) == \
    3 + (((self.number_rounds * 2) + 1) * self.blocksize) + self.number_rounds,\
    "Wrong file size (number of lines)" 

    # Linear layer matrices
    lines_offset = 3
    lines_count = self.number_rounds * self.blocksize
    lin_layer = const_data_split[lines_offset:(lines_offset + lines_count)]
    for r in range(self.number_rounds):
      mat = []
      for s in range(self.blocksize):
        bv = BitVector(bitstring = lin_layer[(r * self.blocksize) + s])
        mat.append(bv)
      self.__lin_layer.append(mat)

    # Round constants
    lines_offset += lines_count 
    lines_count = self.number_rounds
    round_consts = const_data_split[lines_offset:(lines_offset + lines_count)]
    for line in round_consts:
      self.__round_consts.append(BitVector(bitstring = line))    

    # Round key matrices
    lines_offset += lines_count
    lines_count = (self.number_rounds + 1) * self.blocksize
    round_key_mats = const_data_split[lines_offset:(lines_offset + lines_count)]
    for r in range(self.number_rounds + 1):
      mat = []
      for s in range(self.blocksize):
        mat.append(BitVector(bitstring = round_key_mats[(r * self.blocksize) + s]))
      self.__round_key_mats.append(mat)

  def __invert_lin_matrix(self):
  
    self.__lin_layer_inv = []
    for r in range(self.number_rounds):

      # Copy lin_layer
      mat = []
      for i in range(self.blocksize):
        mat.append(self.__lin_layer[r][i].deep_copy())

      # Create (initial identity) matrix, where the
      # inverted matrix will be stored in.
      inv_mat = []
      for i in range(self.blocksize):
        temp_bv = BitVector(intVal = 0, size = self.blocksize)
        temp_bv[i] = 1
        inv_mat.append(temp_bv)

      # Transform to upper triangular matrix
      row = 0
      for col in range(self.keysize):
        if (not mat[row][col]):
          r = row + 1
          while ((r < self.blocksize) and (not mat[r][col])):
            r += 1
          if (r >= self.blocksize):
            continue
          else:
            temp = mat[row]
            mat[row] = mat[r]
            mat[r] = temp
            temp = inv_mat[row]
            inv_mat[row] = inv_mat[r]
            inv_mat[r] = temp
        for i in range (row + 1, self.blocksize):
          if (mat[i][col]):
            mat[i] = mat[i] ^ mat[row]
            inv_mat[i] = inv_mat[i] ^ inv_mat[row]
        row += 1

      # Transform to inverse matrix
      for col in range(self.keysize, 0, -1):
        for r in range(col - 1):
          if (mat[r][col - 1]):
            mat[r] = mat[r] ^ mat[col - 1]
            inv_mat[r] = inv_mat[r] ^ inv_mat[col - 1]

      self.__lin_layer_inv.append(inv_mat)
