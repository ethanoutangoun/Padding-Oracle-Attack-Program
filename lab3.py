import json
from Crypto.Cipher import AES
from base64 import b64decode
import base64
from collections import Counter
import os
import requests
from bs4 import BeautifulSoup
import binascii


def test_cipher(cipher):
    session = requests.Session()
    response = session.get("http://localhost:8080/?enc=" + cipher)
    return response.content == b'404 Not Found'


def bit_switching():
    session = requests.Session()
    response = session.get('http://localhost:8080/eavesdrop')
    cipher = response.cookies.spklit()[29]#

    correct_padding = []
    for i in range(256):
        new = cipher[:-34].decode('utf-8') + str(hex[i][2:]) + cipher[:-32].decode('utf-8')
        if test_cipher(new):
            correct_padding.append(i)


def split_into_blocks(hex_string):
    block_size = 16
    blocks = []
    hex_bytes = bytes.fromhex(hex_string)
    for i in range(0, len(hex_bytes), block_size):
        block = hex_bytes[i:i+block_size]
        blocks.append(block)
    return blocks

#given two 16 byte blocks, xor each byte with each other and return the result
def xor_blocks(b1,b2):
    res = []
    for i in range(16):
        res.append(b1[i] ^ b2[i])

    return bytes(res)




def main():
    
    url = 'http://localhost:8080/eavesdrop'
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    ciphertext = soup.find("font", {"color": "red"}).text.strip()
    blocks = split_into_blocks(ciphertext)#splits hex ciphertext into 16 byte blocks

    #start outer loop top decrypt all blocks

    newBlock = bytearray(blocks[1])
    originalBlock = bytearray(blocks[1])
    #print("eavesdropped ciphertext:")
    #print(ciphertext + "\n")
    #print("ciphertext consists of " + str(len(blocks)) + " blocks")
    #print(blocks)
    #print(len(blocks))



    #####################
    #Plaintext generation
    #####################

    plaintext = bytearray(16)
    foundFlag = False
    for m in range(1,17):
        initialVal = blocks[1][-m]#eventually change -1 to desired index
        newVal = 0
        print("initial ciphertext value: " + str(initialVal))
        #iterate through 256 values of ciphertext to achieve padding success, will return new val
        for i in range(256):
            newBlock[-m] = i

            newCipher = blocks[0] + newBlock + blocks[2]
            if(test_cipher(newCipher.hex()) and initialVal!=i):
                print("new ciphertext byte value: " + str(i))
                newVal = i
                foundFlag = True
        

        if foundFlag is False:
            newVal = initialVal
        else:
            foundFlag = False #reset flag
        
 
        plaintext[-m] = m ^ initialVal ^ newVal #uncover and set plaintext to discovered byte

        #resets newblock so that the last m+1 bytes of the plaintext are padded with m+1
        for i in range(1,m+1):
            newBlock[-i] = originalBlock[-i] ^ plaintext[-i] ^ m+1 #use discovered byte to set padding to desired value, sets plaintext to pad
    
        
        print("\nplaintext at iteration: " + str(m))
        print(plaintext, end= "\n\n")


    

    
  



    
    


    
    


if __name__ == "__main__":
    main()