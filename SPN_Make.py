import random
import hashlib
#SPN cipher with 4 rounds and 16-bit input
rounds=4

#Create parameters of Sbox and reversed Sbox
sbox={0:14, 1:4, 2:13, 3:1, 4:2, 5:15, 6:11, 7:8, 8:3, 9:10, 10:6, 11:12, 12:5, 13:9, 14:0, 15:7}
sbox_inv={14:0, 4:1, 13:2, 1:3, 2:4, 15:5, 11:6, 8:7, 3:8, 10:9, 6:10, 12:11, 5:12, 9:13, 0:14, 7:15}

#Create parameters of Pbox and reversed Pbox
pbox = {0:0, 1:4, 2:8, 3:12, 4:1, 5:5, 6:9, 7:13, 8:2, 9:6, 10:10, 11:14, 12:3, 13:7, 14:11, 15:15}
pbox_inv = {0:0, 4:1, 8:2, 12:3, 1:4, 5:5, 9:6, 13:7, 2:8, 6:9, 10:10, 14:11, 3:12, 7:13, 11:14, 15:15}


#Generate random key
def generate_key():
    k = hashlib.sha1( hex(random.getrandbits(128)).encode('utf-8') ).hexdigest()[2:2+((rounds+1)*4)]
    return k

#Create (rounds) 16-bit keys from key
def key_expansion(k):
    key_split_list=[]
    for i in range(rounds+1):
        key_split_list.append(k[i*4:i*4+4])
    subKeys = [ int(subK,16) for subK in key_split_list]
    return subKeys



#substitute function
def substitute(sbox,text_in):
    text_out = 0
    for i in range(4):
        sbox_in = text_in % (2 ** 4)
        sbox_out = sbox[sbox_in]
        text_out = text_out + (sbox_out << (4 * i))
        text_in = text_in >> 4
    return text_out

#permutation function
def permutate(pbox,text_in):
    text_out = 0
    for i in range(16):
        if(text_in&(1<<i)):
            text_out|=(1<<pbox[i])
    return text_out

#SPN Cipher encrypt function (following lecture slides)
def encrypt(pt,k):
    rounds=4
    keylist=key_expansion(k)
    ct=pt

    for round in range(0,rounds-1): #From first to second last round
        ct=ct^keylist[round] #step 1: XOR key and plaintext

        ct=substitute(sbox,ct) #step 2: Pass through substitution

        ct=permutate(pbox,ct) #step 3: Pass through permutation


    #Final round of SPN
    ct=ct^keylist[-2] #XOR with second last key
 
    ct=substitute(sbox,ct) #Pass through substitution

    ct=ct^keylist[-1] #XOR with last key

    return ct

#SPN Cipher decrypt function
def decrypt(ct,k):
    rounds=4
    keylist=key_expansion(k)
    pt=ct
    
    pt=pt^keylist[-1] #XOR with last key

    pt=substitute(sbox_inv,pt) #Pass through reverse substitution


    for round in range(rounds-1,0,-1):
        pt=pt^keylist[round] #XOR with key)

        pt=permutate(pbox_inv,pt) #Pass through reverse permutation

        pt=substitute(sbox_inv,pt) #Pass through reverse substitution
        
    #Final XOR with first key
    pt=pt^keylist[0]
        
    return pt


