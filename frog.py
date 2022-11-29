#frog encryption decryption
import numpy as np

def frogEncrypt():
    pass

def frogDecrypt():
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

