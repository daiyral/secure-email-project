#frog encryption decryption
import numpy as np
from enum import Enum

BLOCK_SIZE = 10

NUM_ITERATIONS = 8

randomSeed=[
    113, 21,232, 18,113, 92, 63,157,124,193,166,197,126, 56,229,229,
			156,162, 54, 17,230, 89,189, 87,169,  0, 81,204,  8, 70,203,225,
			160, 59,167,189,100,157, 84, 11,  7,130, 29, 51, 32, 45,135,237,
			139, 33, 17,221, 24, 50, 89, 74, 21,205,191,242, 84, 53,  3,230,
			231,118, 15, 15,107,  4, 21, 34,  3,156, 57, 66, 93,255,191,  3,
			85,135,205,200,185,204, 52, 37, 35, 24, 68,185,201, 10,224,234,
			7,120,201,115,216,103, 57,255, 93,110, 42,249, 68, 14, 29, 55,
			128, 84, 37,152,221,137, 39, 11,252, 50,144, 35,178,190, 43,162,
			103,249,109,  8,235, 33,158,111,252,205,169, 54, 10, 20,221,201,
			178,224, 89,184,182, 65,201, 10, 60,  6,191,174, 79, 98, 26,160,
			252, 51, 63, 79,  6,102,123,173, 49,  3,110,233, 90,158,228,210,
			209,237, 30, 95, 28,179,204,220, 72,163, 77,166,192, 98,165, 25,
			145,162, 91,212, 41,230,110,  6,107,187,127, 38, 82, 98, 30, 67,
			225, 80,208,134, 60,250,153, 87,148, 60, 66,165, 72, 29,165, 82,
			211,207,  0,177,206, 13,  6, 14, 92,248, 60,201,132, 95, 35,215,
			118,177,121,180, 27, 83,131, 26, 39, 46, 12]

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
        for i in range (NUM_ITERATIONS):
            for j in range (BLOCK_SIZE):
                plainText[j] = np.bitwise_xor(plainText[j], key[i].xorBu[j]) 
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
                cipherText[key[i]].BombPermu[j] ^= cipherText[j]
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
                if(key[i].BombPermu[j] == 0):
                    k=j
                    while True:
                        k =(k+1) % BLOCK_SIZE
                        if used[k] == 0:
                            break
                    key[i].BombPermu[j] = k
                    l=k
                    while key[i].BombPermu[l] !=k:
                        l=key[i].BombPermu[l]
                    key[i].BombPermu[l]=0
                used[j]=1
                j=key[i].BombPermu[j]
            for ind in range (0, BLOCK_SIZE):
                if ind == BLOCK_SIZE -1:
                    j=0
                else:
                    j=ind+1
                if key[i].BombPermu[ind]==j:
                    if(j == BLOCK_SIZE -1):
                        k=0
                    else:
                        k=j+1
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
            buffer = self.frogEncrypt(buffer, simpleKey)
            size = sizeKey-position
            if(size > BLOCK_SIZE):
                size=BLOCK_SIZE
            for i in range (BLOCK_SIZE):
                if buffer[i]<0:
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
        
def main():
    frog = Frog()
    k = np.empty(32, dtype=np.int32)
    for i in range(0, 32):
        k[i] = i
    intKey=frog.makeKey(k)
    print(intKey.keyE)
    print(intKey.keyD)
    userInput = "Matan".encode('utf-8').hex()
    hex_arr = np.array([int(userInput[i:i+2], 16) for i in range(0, len(userInput), 2)])

    cipherText=frog.frogEncrypt(hex_arr,intKey.keyE)
    print("cipher Text is",cipherText)
    plainText=frog.frogDecrypt(cipherText,intKey.keyD)
    print("decrypted Text is",plainText)


if __name__ == "__main__":
    main()

