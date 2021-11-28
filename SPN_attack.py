from SPN_Make import *
import differential_cryptanalysis_lib as dc_lib
from math import fabs, ceil


def do_sbox(number):
    return sbox[number]


def do_inv_sbox(number):
    return sbox_inv[number]


def do_pbox(state):
    state_temp = 0
    for bitIdx in range(0,16):
        if(state & (1 << bitIdx)):
            state_temp |= (1 << pbox[bitIdx])
    state = state_temp
    return state

def main():

    NUM_P_C_PAIRS = 7000
    SBOX_BITS  = 4
    NUM_SBOXES = 4
    NUM_ROUNDS = 4
    MIN_PROB = 1
    MAX_BLOCKS_TO_BF = 3
    MAX_BLOCKS_TO_BF = 2

    dc_lib.initialize(NUM_P_C_PAIRS,
                      SBOX_BITS,
                      NUM_SBOXES,
                      NUM_ROUNDS,
                      MIN_PROB,
                      MAX_BLOCKS_TO_BF,
                      do_sbox,
                      do_inv_sbox,
                      do_pbox)

    print('Analizing cipher')
    
    diff_characteristics = dc_lib.analize_cipher()
    if len(diff_characteristics) == 0:
        exit('no differential characteristic could be found!')

    #Use differential characteristic with the highest probability
    #Sorted from high to low, use index 0
    diff_characteristic = diff_characteristics[0]

    key = generate_key()
    k_int = int(key, 16)

    #Find which key bits we should obtain
    key_to_find = 0
    for block_num in diff_characteristic[2]:
        k = k_int >> ((NUM_SBOXES - (block_num-1) - 1) * SBOX_BITS)
        k = k & ((1 << SBOX_BITS) - 1)
        key_to_find = (key_to_find << SBOX_BITS) | k

    #Generate the chosen-plaintexts and their ciphertexts
    c_pairs = []
    p_diff = diff_characteristic[1]
    for p1 in range(NUM_P_C_PAIRS):
        c1 = encrypt(p1, key)
        p2 = p1 ^ p_diff
        c2 = encrypt(p2, key)
        c_pairs.append( [c1, c2] )

    print('\nBreaking cipher\n')

    #Obtain the hits given the ciphertexts pairs and the differential characteristic
    hits = dc_lib.get_hits(c_pairs, diff_characteristic)

    #Get the key with the most hits
    maxResult, maxIdx = 0, 0
    for Idx, result in enumerate(hits):
        if result > maxResult:
            maxResult = result
            maxIdx    = Idx

    if maxIdx == key_to_find:
        print('Success!')
        bits_found = '{:b}'.format(maxIdx).zfill(len(diff_characteristic[2])*SBOX_BITS)
        bits_found = [bits_found[i:i+SBOX_BITS] for i in range(0, len(bits_found), SBOX_BITS)]

        blocks_num = list(diff_characteristic[2].keys())

        zipped = list(zip(blocks_num, bits_found))

        
        print('\nObtained key bits:')
        for num_block, bits in zipped:
            print('block {:d}: {}'.format(num_block, bits))

        print("Original Key: "+bin(k_int))

    else:
        print('Failure')

if __name__ == "__main__":
    main()
