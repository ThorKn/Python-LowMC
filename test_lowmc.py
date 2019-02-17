'''
LowMC Blockcipher Tests
Author: Thorsten Knoll
Date: Feb 2019

Description:
Instantiates LowMC in the variants for
'picnic-L1', 'picnic-L3' and 'picnic-L5'.
Tries all testvectors from the Picnic
reference implementation.
'''
from lowmc import LowMC

def main():

  # Instantiate LowMC with L1
  lowmc = LowMC('picnic-L1-FS')
  
  # Vectorset 1 for Picnic1_L1
  key    = bytes([ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  plain  = bytes([ 0xAB, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  cipher = bytes([ 0x0E, 0x30, 0x72, 0x0B, 0x9F, 0x64, 0xD5, 0xC2, \
                   0xA7, 0x77, 0x1C, 0x8C, 0x23, 0x8D, 0x8F, 0x70 ])

  testing(lowmc, "Picnic-L1-FS: Vectorset 1", key, plain, cipher)

  # Vectorset 2 for Picnic1_L1
  key    = bytes([ 0xB5, 0xDF, 0x53, 0x7B, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  plain  = bytes([ 0xF7, 0x7D, 0xB5, 0x7B, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  cipher = bytes([ 0x0E, 0x59, 0x61, 0xE9, 0x99, 0x21, 0x53, 0xB1, \
                   0x32, 0x45, 0xAF, 0x24, 0x3D, 0xD7, 0xDD, 0xC0 ])

  testing(lowmc, "Picnic-L1-FS: Vectorset 2", key, plain, cipher)

  # Vectorset 3 for Picnic1_L1
  key    = bytes([ 0x08, 0x4c, 0x2a, 0x6e, 0x19, 0x5d, 0x3b, 0x7f, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  plain  = bytes([ 0xf7, 0xb3, 0xd5, 0x91, 0xe6, 0xa2, 0xc4, 0x80, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  cipher = bytes([ 0x91, 0x5c, 0x63, 0x21, 0xd7, 0x86, 0x46, 0xb6, \
                   0xc7, 0x65, 0x43, 0xff, 0xb8, 0x52, 0x3b, 0x4d ])

  testing(lowmc, "Picnic-L1-FS: Vectorset 3", key, plain, cipher)

  # Instantiate LowMC with L3
  lowmc = LowMC('picnic-L3-FS')

  # Vectorset 1 for Picnic1_L3
  key    = bytes([ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  plain  = bytes([ 0xAB, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  cipher = bytes([ 0xA8, 0x5B, 0x82, 0x44, 0x34, 0x4A, 0x2E, 0x1B, \
                   0x10, 0xA1, 0x7B, 0xAB, 0x04, 0x30, 0x73, 0xF6, \
                   0xBB, 0x64, 0x9A, 0xE6, 0xAF, 0x65, 0x9F, 0x6F ])

  testing(lowmc, "Picnic-L3-FS: Vectorset 1", key, plain, cipher)

  # Vectorset 2 for Picnic1_L3
  key    = bytes([ 0xB5, 0xDF, 0x53, 0x7B, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  plain  = bytes([ 0xF7, 0x7D, 0xB5, 0x7B, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  cipher = bytes([ 0x21, 0x0B, 0xBC, 0x4A, 0x43, 0x4B, 0x32, 0xDB, \
                   0x1E, 0x85, 0xAE, 0x7A, 0x27, 0xFE, 0xE9, 0xE4, \
                   0x15, 0x82, 0xFA, 0xC2, 0x1D, 0x03, 0x5A, 0xA1 ])

  testing(lowmc, "Picnic-L3-FS: Vectorset 2", key, plain, cipher)

  # Vectorset 3 for Picnic1_L3
  key    = bytes([ 0xF7, 0x7D, 0xB5, 0x7B, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  plain  = bytes([ 0xB5, 0xDF, 0x53, 0x7B, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  cipher = bytes([ 0xE4, 0x82, 0xBC, 0xF9, 0xAD, 0x2C, 0x04, 0x48, \
                   0x31, 0x48, 0xD4, 0x6F, 0xBE, 0x1F, 0x8B, 0x51, \
                   0x46, 0x0D, 0xCC, 0x3E, 0x8E, 0xFB, 0x31, 0x01 ])

  testing(lowmc, "Picnic-L3-FS: Vectorset 3", key, plain, cipher)

  # Instantiate LowMC with L5
  lowmc = LowMC('picnic-L5-FS')

  # Vectorset 1 for Picnic1_L5
  key    = bytes([ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  plain  = bytes([ 0xAB, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  cipher = bytes([ 0xB8, 0xF2, 0x0A, 0x88, 0x8A, 0x0A, 0x9E, 0xC4, \
                   0xE4, 0x95, 0xF1, 0xFB, 0x43, 0x9A, 0xBD, 0xDE, \
                   0x18, 0xC1, 0xD3, 0xD2, 0x9C, 0xF2, 0x0D, 0xF4, \
                   0xB1, 0x0A, 0x56, 0x7A, 0xA0, 0x2C, 0x72, 0x67 ])

  testing(lowmc, "Picnic-L5-FS: Vectorset 1", key, plain, cipher)

  # Vectorset 2 for Picnic1_L5
  key    = bytes([ 0xF7, 0x7D, 0xB5, 0x7B, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  plain  = bytes([ 0xB5, 0xDF, 0x53, 0x7B, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  cipher = bytes([ 0xEE, 0xEC, 0xCE, 0x6A, 0x58, 0x4A, 0x93, 0x30, \
                   0x6D, 0xAE, 0xA0, 0x75, 0x19, 0xB4, 0x7A, 0xD6, \
                   0x40, 0x2C, 0x11, 0xDD, 0x94, 0x2A, 0xA3, 0x16, \
                   0x65, 0x41, 0x44, 0x49, 0x77, 0xA2, 0x14, 0xC5 ])

  testing(lowmc, "Picnic-L5-FS: Vectorset 2", key, plain, cipher)

  # Vectorset 3 for Picnic1_L5
  key    = bytes([ 0xB5, 0xDF, 0x53, 0x7B, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  plain  = bytes([ 0xF7, 0x7D, 0xB5, 0x7B, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])
  cipher = bytes([ 0x03, 0x37, 0x33, 0x26, 0xC0, 0xF5, 0x0E, 0x3B, \
                   0x6B, 0x2E, 0x1C, 0xE8, 0xF9, 0x43, 0x0F, 0xF5, \
                   0xEB, 0x0E, 0xC3, 0x45, 0xC7, 0x27, 0xA4, 0x74, \
                   0x8F, 0xCF, 0x73, 0x17, 0x9D, 0x48, 0xE7, 0x9B ])

  testing(lowmc, "Picnic-L5-FS: Vectorset 3", key, plain, cipher)


def testing(lowmc, vectorset, key, plain, cipher):

  print("------------------------------")
  print(vectorset)
  print("------------------------------")
  lowmc.set_priv_key(key)
  print("start encryption")
  cipher_new = lowmc.encrypt(plain)
  print("start decryption")
  plain_new = lowmc.decrypt(cipher)
  print("plaintext:             " + plain.hex().upper())
  print("calculated ciphertext: " + cipher_new.hex().upper())
  print("expected   ciphertext: " + cipher.hex().upper())
  print("calculated plaintext:  " + plain_new.hex().upper())
  if (cipher_new == cipher) and (plain_new == plain):
    print("test successful")
  else:
    print("test failed")

if __name__ == '__main__':
    main()
