from Crypto.Cipher import AES
import binascii

# Create a Zeroing IV
zero_iv = bytearray(AES.block_size)

# Compute an IV that once XORed provides us with a plaintext that has a valid padding of 1
valid_padding_iv = bytearray(AES.block_size)
valid_padding_iv[-1] = 1

# XOR the last byte of valid_padding_iv with 1 and store the result in the last byte of zero_iv
zero_iv[-1] = valid_padding_iv[-1] ^ 1

# Derive a new IV that sets the final byte to 2 and try to compute the penultimate byte to 2 as well
for i in range(2, AES.block_size + 1):
    prev_byte = zero_iv[-i+1]
    new_iv = bytearray(AES.block_size)
    new_iv[-i] = prev_byte ^ (i - 1) ^ i
    for j in range(i-1, AES.block_size):
        new_iv[j] = zero_iv[j] ^ (i - 1) ^ i

    # Get the penultimate byte from the new_iv and XOR it with 2 to generate the penultimate byte of the zero_iv
    zero_iv[-i] = new_iv[-i] ^ 2

# Decrypt the ciphertext using zero_iv as the IV
cipher = AES.new(key, AES.MODE_CBC, zero_iv)
plaintext = cipher.decrypt(ciphertext)

# XOR zero_iv with the original IV to get the decrypted plaintext message
decrypted_plaintext = bytes(x ^ y for x, y in zip(zero_iv, iv)) + plaintext
