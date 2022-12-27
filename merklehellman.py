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
        encrypted_msg = [0]*len(msg)
        i = 0
        for ch in msg:
            arr[i] = format(ch, '16b')
            i += 1
        for i in range(len(arr)):
            for j in range(len(arr[i])):
                if arr[i][j] == '1':
                    encrypted_msg[i] += self.public_key[j]
        return encrypted_msg
        
    def modular_inverse(self, a, m):
    # Calculate the modular inverse using the pow() function
        for x in range(1, m):
            if (((a % m) * (x % m)) % m == 1):
                return x
        return -1
    
            
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
        pText = [0]*len(msg)
        for i in range(len(msg)):
            msg[i] = msg[i] * r_tag % self.private_key[1]
            m_idx = self.find_index_greedy(self.private_key[0], msg[i])
            for j in range(len(m_idx)):
                pText[i] += pow(2, 16 - m_idx[j])
        return pText
      
    def get_keys(self):
        temp_sum = 0
        w = [0]*paramaters.BLOCK_SIZE
        b = [0]*paramaters.BLOCK_SIZE
        for i in range(len(w)):
            temp_sum += temp_sum + i + 1
            w[i] = temp_sum
        temp_sum += temp_sum
        q = temp_sum + random.randint(1, 128)
        r = random.randint(1, q)
        while math.gcd(r,q) != 1:
            r = random.randint(1, 255)
        for i in range(len(b)):
            b[i] = r*w[i] % q
        return b, q, r, w
    