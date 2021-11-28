# Cx4010 Project on attacks on SPN Cipher
## This repository contain the implementation of a simple SPN Cipher and the use of differential cryptanalysis on it
## Implementation of SPN Cipher with 16-bit cipher text and round keys of 16-bit
1) Expansion of key to unique 16-bit round keys
2) For all rounds except the last one, XOR text with round key, pass through substitution box then permutation box
3) For the last round, XOR with round key, then pass through substitution box, finally XOR with last round key
For decryption, proceed in opposite order (i.e. XOR with last round key, then pass through reversed substitution box,...)
## Applying differential cryptanalysis
Lets say input x1 and x2 produces output y1 and y2 respectively.
Let X = x1 XOR x2 and Y = y1 XOR y2.
In a perfect randomising cipher, probability that Y occurs given X is 1/2^n where n is number of bits of X.
However, no cipher is perfect and differential cryptanalysis finds the scenario where probability Y given X is very high.
### 1) We compute the differential table of the sbox
For a 4x4 S-box, all difference pairs (X,Y) and be examined and probability Y given X can be calculated with inputs x1 and x2.
We can tabularize the data on a differential table with X representing rows and Y representing columns.
### 2) We contruct differential characteristics
We can concateninate dfference pairs of S-boxes and contruct a differential characteristic of certain S-box difference pairs in each round,
such that a differential involves plaintexts bits and data bits to the input of the last round of S-boxes.
By multiplying the probability throughout the S-boxes, we can obtain the probability of a certain ciphertext given plaintext.
### 3) Extracting key bits
We then generate a large number of plaintext/ciphertext pairs using randomly generated subkeys.
Then we can use the chosen differential characteristic to obtain bits of the last round key.

## Research and design
References:

https://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf (Howard M. Heys tutorial on cryptanalysis)

https://github.com/physics-sec/Differential-Cryptanalysis (Used as references for source code of differential cryptanalysis and key generation)
            
## Use of code
Run SPN_attack - imports SPN_Make and differential_cryptanalysis_lib
## Motivation
A 4 round SPN Cipher is considered to be a weak cipher. By implementing a basic differential cryptanalysis, we can study the basics of cryptanalysis and how the process of attacking by hackers is done.
