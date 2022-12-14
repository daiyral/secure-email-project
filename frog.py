#frog encryption decryption
import numpy as np
from enum import Enum
import random
import binascii
from paramaters import *
class ENCRYPTION(Enum):
    ENCRYPT = False
    DECRYPT = True
class FrogIterKey:
    def __init__(self):
        self.xorBu =  np.empty(BLOCK_SIZE, dtype = np.int32)
        self.SubstPermu = np.empty(256,dtype=np.int32)
        self.BombPermu = np.empty(BLOCK_SIZE,dtype=np.int32)
    
    def size():
        return BLOCK_SIZE*2+256

    def setValue(self,i, value):
        if value < 0:
            value = 256  + value
        if i < BLOCK_SIZE:
            self.xorBu[i] = value
        elif i < BLOCK_SIZE + 256:
            self.SubstPermu[i-BLOCK_SIZE] = value
        else:
            self.BombPermu[i-BLOCK_SIZE-256] = value
    
    def getValue(self,i):
        if i < BLOCK_SIZE:
            return self.xorBu[i]
        elif i < BLOCK_SIZE + 256:
            return self.SubstPermu[i-BLOCK_SIZE]
        else:
            return self.BombPermu[i-BLOCK_SIZE-256]

    def copyFrom(self,origin):
        for i in range (len(origin.xorBu)):
            self.xorBu[i] = origin.xorBu[i]
        for i in range (len(origin.SubstPermu)):
            self.SubstPermu[i] = origin.SubstPermu[i]
        for i in range (len(origin.BombPermu)):
            self.BombPermu[i] = origin.BombPermu[i]

class FrogInternalKey:
    def __init__(self):
        self.internalKey = [FrogIterKey() for i in range(NUM_ITERATIONS)]
        self.keyE=[FrogIterKey() for i in range(NUM_ITERATIONS)]
        self.keyD=[FrogIterKey() for i in range(NUM_ITERATIONS)]

    def setValue(self,index,value):
        self.internalKey[index/FrogIterKey.size()].setValue(index%FrogIterKey.size(),value)
    
    def getValue(self,index):
        return self.internalKey[index/FrogIterKey.size()].getValue(index%FrogIterKey.size())


class Frog:
    def __init__(self):
        pass
    
    def frogEncrypt(self, plainText, key):
        #Encrypt plainText using internalKey - (internal cycle) See B.1.1  
        for i in range (0, NUM_ITERATIONS):
            for j in range (0, BLOCK_SIZE):
                plainText[j] = plainText[j] ^ key[i].xorBu[j]
                if plainText[j]<0:
                    plainText[j] = key[i].SubstPermu[plainText[j]+256]
                else:
                    plainText[j] = key[i].SubstPermu[plainText[j]]
                if j< BLOCK_SIZE -1:
                    plainText[j+1]= plainText[j+1] ^ plainText[j]
                else:
                    plainText[0] = plainText[0] ^ plainText[BLOCK_SIZE-1]
                plainText[key[i].BombPermu[j]] ^= plainText[j] 
        return plainText
        
    def frogDecrypt(self, cipherText, key):
        for i in reversed(range (0, NUM_ITERATIONS)):
            for j in reversed(range (0, BLOCK_SIZE)):
                cipherText[key[i].BombPermu[j]] ^= cipherText[j]
                if(j< BLOCK_SIZE -1):
                    cipherText[j+1] = cipherText[j+1] ^ cipherText[j]
                else:
                    cipherText[0] = cipherText[0] ^ cipherText[BLOCK_SIZE-1]
                if cipherText[j]<0:
                    cipherText[j] = key[i].SubstPermu[cipherText[j]+256]
                else:
                    cipherText[j] = key[i].SubstPermu[cipherText[j]]
                cipherText[j] = cipherText[j] ^ key[i].xorBu[j]
        return cipherText

    def makeInternalKey(self, decrypting, keyorigin):
        used = np.empty(BLOCK_SIZE, dtype=np.int8)
        key= [FrogIterKey() for i in range(NUM_ITERATIONS)]
        k=0
        l=0
        h=0
        for i in range(0, NUM_ITERATIONS):
            key[i]=FrogIterKey()
            key[i].copyFrom(keyorigin[i])
        for i in range (0, NUM_ITERATIONS):
            key[i].SubstPermu=self.makePermutation(key[i].SubstPermu)
            if(decrypting.value):
                key[i].SubstPermu=self.invertPermutation(key[i].SubstPermu)
            
            key[i].BombPermu=self.makePermutation(key[i].BombPermu)
            for j in range (0, BLOCK_SIZE):
                used[j]=0
            for j in range (0, BLOCK_SIZE-1):
                if(key[i].BombPermu[h] == 0):
                    k=h
                    while True:
                        k =(k+1) % BLOCK_SIZE
                        if used[k] == 0:
                            break
                    key[i].BombPermu[h] = k
                    l=k
                    while key[i].BombPermu[l] !=k:
                        l=key[i].BombPermu[l]
                    key[i].BombPermu[l]=0
                used[h]=1
                h=key[i].BombPermu[h]
            for ind in range (0, BLOCK_SIZE):
                if ind == BLOCK_SIZE -1:
                    h=0
                else:
                    h=ind+1
                if key[i].BombPermu[ind]==h:
                    if(h == BLOCK_SIZE -1):
                        k=0
                    else:
                        k=h+1
                    key[i].BombPermu[ind]=k
            
        return key

    def hashKey(self, binaryKey):
        buffer = np.empty(BLOCK_SIZE, dtype=np.int8)
        simpleKey = [FrogIterKey() for i in range(NUM_ITERATIONS)]
        internalKey= [FrogIterKey() for i in range(NUM_ITERATIONS)]
        for i in range(0, NUM_ITERATIONS):
            simpleKey[i]=FrogIterKey()
            internalKey[i]=FrogIterKey()
        keyLen=len(binaryKey)
        sizeKey=FrogIterKey.size() * NUM_ITERATIONS
        iSeed=0
        iFrase=0
        for i in range(0, sizeKey):
            simpleKey[i//FrogIterKey.size()].setValue(i%FrogIterKey.size(), randomSeed[iSeed]^binaryKey[iFrase])
            if iSeed<250:
                iSeed=iSeed+1
            else:
                iSeed=0
            if iFrase<keyLen-1:
                iFrase=iFrase+1
            else:
                iFrase=0
        simpleKey=self.makeInternalKey(ENCRYPTION.ENCRYPT, simpleKey)
        for i in range(0, BLOCK_SIZE):
            buffer[i]=0
        last = keyLen-1
        if(last>BLOCK_SIZE):
            last=BLOCK_SIZE-1
        for i in range(0, last+1):
            buffer[i] ^= binaryKey[i]
        buffer[0] ^= keyLen

        position=0

        while True:
            buffer= self.frogEncrypt(buffer, simpleKey)
            size =sizeKey-position
            if(size> BLOCK_SIZE):
                size=BLOCK_SIZE
            for i in range (0, BLOCK_SIZE):
                if(buffer[i]<0):
                    internalKey[(position+i)//FrogIterKey.size()].setValue((position+i)%FrogIterKey.size(), buffer[i]+256)
                else:
                    internalKey[(position+i)//FrogIterKey.size()].setValue((position+i)%FrogIterKey.size(), buffer[i])
            position = position + size
            if position == sizeKey:
                break
        return internalKey



    def makePermutation(self, permu):

        #Receives an arbitarty byte arror of (lastElem -1) elements and
        #returns a permutation with values between 0 and lastElem.
        #Reference Text: section B.1.3  
        use = np.empty(256, dtype=np.int8) # 256 length byte array
        lastElem = len(permu) -1
        last = lastElem
        j=0
        #initialize use array
        for i in range(0, lastElem+1):
            use[i]=i
        
        for i in range(0, lastElem):
            j = (j+permu[i]) % (last + 1)
            permu[i] = use[j]
            # Remove use[index] value from use array 
            if j<last:
                for k in range(j, last):
                    use[k] = use[k+1]
            last = last -1
            if j > last:
                j = last
        permu[lastElem] = use[0]        
        return permu

    def invertPermutation(self, origPermu):
        #Receives a permutation and returns its inverse
        invPermu = np.empty(256, dtype=np.int8)
        for i in range(0, len(origPermu)):
            invPermu[origPermu[i]] = i
        return invPermu

    def makeKey(self, k):
        intKey = FrogInternalKey()
        intKey.internalKey = self.hashKey(k)
        intKey.keyE=self.makeInternalKey(ENCRYPTION.ENCRYPT, intKey.internalKey)
        intKey.keyD=self.makeInternalKey(ENCRYPTION.DECRYPT, intKey.internalKey)
        return intKey
    
# def main():
#     k = np.empty(16, dtype=np.int8)
#     for i in range(0, 16):
#         k[i] = i
#     pt=np.empty(BLOCK_SIZE, dtype=np.int8)
#     for i in range(0, BLOCK_SIZE):
#         pt[i] = i
#     intKey=makeKey(k)
#     print("my text is ", pt)
#     cipherText=frogEncrypt(pt, intKey.keyE)
#     print("my encrypted text is ",cipherText)

#     plainText=frogDecrypt(cipherText, intKey.keyD)
#     print("my decrypted text is ",plainText)

