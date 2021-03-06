'''
---------------------------------------------------
Generator for LowMC constants and matrices

The original file is from the LowMC Github Repo:
https://github.com/LowMC/lowmc/generate_matrices.py

Version at Github HEAD:
3994bc857661ac33134b36163b131a215f0fe9c3

Modified by Thorsten Knoll, Feb 2019

LowMC and this file are published 
under MIT Licence. See the LICENCE.md file.
---------------------------------------------------
'''

import sys
from BitVector import BitVector

# Parameterset Picnic
blocksize = None
keysize = None
rounds = None
filename = None

def main():
    ''' Use the global parameters `blocksize`, `keysize` and `rounds`
        to create the set of matrices and constants for the corresponding
        LowMC instance. Save those in a file named
        `matrices_and_constants.dat`.
    '''

    # Parse args
    param = sys.argv[1]
    if (param == 'picnic-L1'):
      blocksize = 128
      keysize   = 128
      rounds    = 20
      filename  = 'picnic-L1.dat'
    elif (param == 'picnic-L3'):
      blocksize = 192
      keysize   = 192
      rounds    = 30
      filename  = 'picnic-L3.dat'
    elif (param == 'picnic-L5'):
      blocksize = 256
      keysize   = 256
      rounds    = 38
      filename  = 'picnic-L5.dat'

    gen = grain_ssg()

    linlayers = []
    for _ in range(rounds):
        linlayers.append(instantiate_matrix(blocksize, blocksize, gen))

    round_constants = []
    for _ in range(rounds):
        constant = [next(gen) for _ in range(blocksize)]
        round_constants.append(constant)

    roundkey_matrices = []
    for _ in range(rounds + 1):
        mat = instantiate_matrix(blocksize, keysize, gen)
        roundkey_matrices.append(mat)

    with open(filename, 'w') as matfile:
        s = str(blocksize) + '\n' + str(keysize) + '\n' + str(rounds) + '\n'
        matfile.write(s)
        for r in range(rounds):
            s = ''
            for row in linlayers[r]:
                bv = BitVector(bitlist = row)
                s += str(bv) + '\n'
            matfile.write(s)

        for r in range(rounds):
            bv = BitVector(bitlist = round_constants[r])
            s = str(bv) + '\n'
            matfile.write(s)

        for r in range(rounds + 1):
            s = ''
            for row in roundkey_matrices[r]:
                bv = BitVector(bitlist = row)
                s += str(bv) + '\n'
            matfile.write(s)

def instantiate_matrix(n, m, gen):
    ''' Instantiate a matrix of maximal rank using bits from the
        generatator `gen`.
    '''
    while True:
        mat = []
        for _ in range(n):
            row = []
            for _ in range(m):
                row.append(next(gen))
            mat.append(row)
        if rank(mat) >= min(n, m):
            return mat

def rank(matrix):
    ''' Determine the rank of a binary matrix. '''
    # Copy matrix
    mat = [[x for x in row] for row in matrix]
    
    n = len(matrix)
    m = len(matrix[0])
    for c in range(m):
        if c > n - 1:
            return n
        r = c
        while mat[r][c] != 1:
            r += 1
            if r >= n:
                return c
        mat[c], mat[r] = mat[r], mat[c]
        for r in range(c + 1, n):
            if mat[r][c] == 1:
                for j in range(m):
                    mat[r][j] ^= mat[c][j]
    return m


def grain_ssg():
    ''' A generator for using the Grain LSFR in a self-shrinking generator. '''
    state = [1 for _ in range(80)]
    index = 0
    # Discard first 160 bits
    for _ in range(160):
        state[index] ^= state[(index + 13) % 80] ^ state[(index + 23) % 80]\
                        ^ state[(index + 38) % 80] ^ state[(index + 51) % 80]\
                        ^ state[(index + 62) % 80]
        index += 1
        index %= 80
    choice = False
    while True:
        state[index] ^= state[(index + 13) % 80] ^ state[(index + 23) % 80]\
                        ^ state[(index + 38) % 80] ^ state[(index + 51) % 80]\
                        ^ state[(index + 62) % 80]
        choice = state[index]
        index += 1
        index %= 80
        state[index] ^= state[(index + 13) % 80] ^ state[(index + 23) % 80]\
                        ^ state[(index + 38) % 80] ^ state[(index + 51) % 80]\
                        ^ state[(index + 62) % 80]
        if choice == 1:
            yield state[index]
        index += 1
        index %= 80


if __name__ == '__main__':
    main()

