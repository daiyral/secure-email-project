import math
import numpy as np
import random
import paramaters

MerkleHellman_block_size = 16

class MerkleHellman:
    def __init__(self) -> None:
        self.public_key, q, r, w = self.get_keys()
        self.private_key = [w,q,r]
        
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
    
    def encrypt(self, msg):
        arr = [""]*len(msg)
        self.encrypted_msg = np.empty(len(msg), dtype=np.int32)
        i = 0
        for ch in msg:
            arr[i] = format(ch, '16b')
            i += 1
        for i in range(len(arr)):
            for j in range(len(arr[i])):
                if arr[i][j] == '1':
                    self.encrypted_msg[i] += self.public_key[j]
        return self.encrypted_msg
        
    def modular_inverse(self, a, m):
    # Calculate the modular inverse using the pow() function
        inv = pow(a, m - 2, m)
        return inv
    
            
    def find_index_greedy(self,weights, capacity):
    # Sort the values in decreasing order
        weights = sorted(weights, reverse=True)
        chosen_items = []
        i = 0
        while capacity > 0:
            if weights[i] <= capacity:
                chosen_items.append(len(weights) - i - 1)
                capacity -= weights[i]
                weights[i] = 0
            i += 1
       
        return chosen_items
    
    def decrypt(self, msg):
        r_tag = self.modular_inverse(self.private_key[2], self.private_key[1]) 
        pText = np.empty(len(msg), dtype=np.int16)
        for i in range(len(msg)):
            pText[i] = 0
            msg[i] = msg[i] * r_tag % self.private_key[1]
            m_idx = self.find_index_greedy(self.private_key[0], msg[i])
            for j in range(len(m_idx)):
                pText[i] += pow(2, 16 - m_idx[j])
            
            # 4,3,1 > 000011010
      
    def get_keys(self):
        temp_sum = 0
        w = np.empty(MerkleHellman_block_size, dtype=np.int16)
        b = np.empty(MerkleHellman_block_size, dtype=np.int16)
        for i in range(len(w)):
            temp_sum += i + 1
            w[i] = temp_sum
        q = random.randint(temp_sum, pow(2, 16)-1)
        r = random.randint(1, 255)
        while math.gcd(r,q) != 1:
            r = random.randint(1, 255)
        for i in range(len(b)):
            b[i] = r*w[i] % q
        return b, q, r, w
    