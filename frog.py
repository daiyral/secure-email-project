#frog encryption decryption
import numpy as np

BLOCK_SIZE = 16

NUM_ITERATIONS = 8

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
        self.xorBu = origin.xorBu
        self.SubstPermu = origin.SubstPermu
        self.BombPermu = origin.BombPermu



def frogEncrypt(plainText, key):
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
            plainText[key[i].bombPermu[j]] ^= plainText[j] 
    return plainText
    
def frogDecrypt():
    pass

def createInternalKey(key):
    pass

def makePermutation( permu):

    #Receives an arbitarty byte arror of (lastElem -1) elements and
    #returns a permutation with values between 0 and lastElem.
	#Reference Text: section B.1.3  
    use = np.empty(256, dtype=np.int8) # 256 length byte array
    lastElem = len(permu) -1
    last = lastElem
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

def main():
    pass

if __name__ == "__main__":
    main()

