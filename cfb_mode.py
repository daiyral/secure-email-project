import paramaters
import numpy as np

def encrypt(enc_alg, iv, key, msg_arr):
    c_i = enc_alg(np.copy(iv), key) # first block is iv
    i = 0
    cText = [0]*len(msg_arr)
    while i < len(msg_arr):
        if i + paramaters.BLOCK_SIZE > len(msg_arr): 
            for j in range(0, len(msg_arr) - i):
                cText[j+i] = msg_arr[j+i] ^ c_i[j]
            break
        for j in range(0, paramaters.BLOCK_SIZE):
            cText[j+i] = msg_arr[j+i] ^ c_i[j]
        c_i = enc_alg(np.copy(cText[i:i+paramaters.BLOCK_SIZE]), key)
        i += paramaters.BLOCK_SIZE
    return cText

def decrypt(enc_alg, iv, key, cText):
    pText = [0]*len(cText)
    c_i = enc_alg(np.copy(iv), key) # first block is iv
    i = 0
    while i < len(pText):
        if i + paramaters.BLOCK_SIZE > len(pText):
            for j in range(0, len(pText) - i):
                pText[j+i] = cText[j+i] ^ c_i[j]
            break
        for j in range(0, paramaters.BLOCK_SIZE):
            pText[j+i] = cText[j+i] ^ c_i[j]
        c_i = enc_alg(np.copy(cText[i:i+paramaters.BLOCK_SIZE]), key)
        i += paramaters.BLOCK_SIZE
    return pText