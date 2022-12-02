import random as rand
from datetime import datetime


def gcd(m,n):
    
    while m != n:
        if m > n:
            m=m-n
        else:
            n=n-m
    return m


def sort(arr):
    for i in range(0,8):
        for j in range(i+1,9):
            if arr[i]>arr[j]:
                temp=arr[i]
                arr[i]=arr[j]
                arr[j]=temp
    return arr


def sum (a):
    sum=0
    for i in range(0,8):
        sum=sum+a[i]
    return sum


def main():
    print ("\nInitialising the super-increasing sequence")
    w=[]
    b=[]
    a=[]
    c=0
    for i in range(0,9):
        b[i]=0
        a[i]=0
    for i in range(0,8):
        w[i]=rand.seed(datetime.now().timestamp())%1000

    qt=sum(w)
    q=rand.seed(datetime.now().timestamp())%10000

    while q<qt:
        q=rand.seed(datetime.now().timestamp())%10000

    w=sort(w) 
    print("\nThe super-increasing sequence is: ")
    print (*w,sep='\t')
    print("\nThe value of sigma W is {qt}")
    print("\nThe value of q chosen is {q}")

    while True:
        r=rand.seed(datetime.now().timestamp())
        while gcd(q,r)!=1:
            r=rand.seed(datetime.now().timestamp())
        if q>=r:
            break

    print("\nThe value of r chosen is {r}")
    for i in range(0,8):
        b[i]=(r*w[i])%q

    print("\nThe public key beta is ")
    print (*b,sep='\t')
    print("\nEnter the 8-bit string to be encrypted")

    for i in range(0,8):
        a[i]=input()

    print("\nThe Encrypted Ciphertext is")

    for i in range(0,8):
        c=c+(a[i]*b[i])

    print("{c}\t")
    

if __name__=="__main__":
    main()