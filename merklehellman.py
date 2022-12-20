import math
import numpy as np
import random
import paramaters
class MerkleHellman:
    def __init__(self) -> None:
        pass
    
    def sort(self, arr):
        for i in range(len(arr)):
            for j in range(i+1,len(arr)):
                if arr[i]>arr[j]:
                    temp=arr[i]
                    arr[i]=arr[j]
                    arr[j]=temp
        return arr


    def sum(self, a):
        sum=0
        for i in range(len(a)):
            sum=sum+a[i]
        return sum
    
    def get_public_key(self):
        temp_sum = 0
        w = np.empty(paramaters.BLOCK_SIZE, dtype=np.int8)
        b = np.empty(paramaters.BLOCK_SIZE, dtype=np.int8)
        for i in range(len(w)):
            temp_sum += i + 1
            w[i] = temp_sum
        q = random.randint(temp_sum, 255)
        r = random.randint(1, 255)
        while math.gcd(r,q) != 1:
            r = random.randint(1, 255)
        for i in range(len(b)):
            b[i] = r*w[i] % q
        return b