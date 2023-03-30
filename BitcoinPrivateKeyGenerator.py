# Python version: 3.11.0 (64-bit, x64)
# Updated: 30/03/2023
# Licence: MIT License
# Contact: satoshi.amd@gmail.com

# resources:
# https://en.wikipedia.org/wiki/SHA-2
# https://blog.boot.dev/cryptography/how-sha-2-works-step-by-step-sha-256/
# https://learnmeabitcoin.com/technical/base58
# https://learnmeabitcoin.com/technical/wif 
# https://en.bitcoin.it/wiki/Base58Check_encoding
# https://medium.com/@farukterzioglu/bitcoinde-private-key-a5d79eeda0f1
# https://learn.saylor.org/mod/page/view.php?id=36323


def sha256_binary_input(input_binary: str):
  # input binary array length must be multiple of 512. if it is not 512^x, it is be modified to resize to 512^x
  # last 64 bit is for the binary representation of length of binary array of input
  # binary representation of length of original binary array of input must be stored before binary data manipulation of input_binary
  input_length = len(input_binary)
  formatted_length = input_length + 1 + 64
  formatted_length = 512 + formatted_length - formatted_length % 512



  # firstly, bit '1' added last to binary data
  # after filled with bit '0' to resize array to length of (512^x - 64)
  # lastly, binary representation of length of original binary array of input is filled for last 64 bit
  input_binary += "1"
  input_binary = input_binary[::-1].zfill(formatted_length - 64)[::-1]
  input_binary += bin(input_length)[2:].zfill(64)



  # HASH VALUES
  # these values are constants
  # they repsent fractional part of square root of first 8 prime numbers (2, 3, 5, 7, 11, 13, 17, 19)
  # h0 = pow(2, -2) % 1.0
  # h1 = pow(3, -2) % 1.0
  # ...
  # h7 = pow(19, -2) % 1.0
  h0 = 0x6A09E667 # = 0b01101010000010011110011001100111
  h1 = 0xBB67AE85 # = 0b10111011011001111010111010000101
  h2 = 0x3C6EF372 # = 0b00111100011011101111001101110010
  h3 = 0xA54FF53A # = 0b10100101010011111111010100111010
  h4 = 0x510E527F # = 0b01010001000011100101001001111111
  h5 = 0x9B05688C # = 0b10011011000001010110100010001100
  h6 = 0x1F83D9AB # = 0b00011111100000111101100110101011
  h7 = 0x5BE0CD19 # = 0b01011011111000001100110100011001



  # ROUND CONSTANTS
  # these values are constants
  # they repsent fractional part of cube root of first 64 prime numbers (2-311)
  # k[0] = pow(2, -3) % 1.0
  # k[1] = pow(3, -3) % 1.0
  # ...
  # k[63] = pow(311, -3) % 1.0
  k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814 ,0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]




  # this is output of SHA256 algorithm
  hash_hexadecimal = ""




  # if modified input is larger than 512 bit
  # it is seperated by 512 bit parts
  for p in range(int(len(input_binary) / 512)):

    # each part (which is 512 bit sized) is resized to 2048 bit size
    # 2048 bit = 64 * 32-bit word
    # part consist of 16 word (512/32)
    # so 48 word with bit '0' is padded to part for resizing to 64 word
    part = input_binary[512*p : 512*(p+1)]
    words = []
    for i in range(16):
      words.append(part[32*i : 32*(i+1)])
    for i in range(48):
      words.append(bin(0)[2:].zfill(32))
      # bin() function returns 0b.... value and trims leading zeros if exist
      # '[2:].zfill(32)' is used to format binary string

    # the padded 48 word is modifed with right rotate and right shift operations
    for index in range(48):
      i = index + 16
      rr7  = int(words[i-15][32-7:] + words[i-15][:32-7], 2)    # right rotate 7
      rr18 = int(words[i-15][32-18:] + words[i-15][:32-18], 2)  # right rotate 18
      rs3  = int(words[i-15], 2) >> 3                           # right shift 3
      s0 = rr7 ^ rr18 ^ rs3

      rr17 = int(words[i-2][32-17:] + words[i-2][:32-17], 2)    # right rotate 17
      rr19 = int(words[i-2][32-19:] + words[i-2][:32-19], 2)    # right rotate 19
      rs10 = int(words[i-2], 2) >> 10                           # right shift 10
      s1 = rr17 ^ rr19 ^ rs10

      # '0xFFFFFFFF masking' is used for 2^32 modulo addition
      w = ((((((int(words[i-16], 2) + s0) & 0xFFFFFFFF) + int(words[i-7], 2)) & 0xFFFFFFFF) + s1) & 0xFFFFFFFF)

      # bin() function returns 0b.... value and trims leading zeros if exist
      # '[2:].zfill(32)' is used to format binary string
      words[i] = bin(w)[2:].zfill(32)
      
    # HASH VALUES (h0-h7) are assigned to a-h values respectively
    # so hash values (h0-h7) and these new values (a-b) change in every iteration (p) for 512-bit part of input
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    f = h5
    g = h6
    h = h7

    # a-b values are modified
    for i in range(64):
      we = (bin(e)[2:].zfill(32))
      rr6 = int(we[32-6:] + we[:32-6], 2)       # right rotate 6
      rr11 = int(we[32-11:] + we[:32-11], 2)    # right rotate 11
      rr25 = int(we[32-25:] + we[:32-25], 2)    # right rotate 25
      S1 = rr6 ^ rr11 ^ rr25
      ch = (e & f) ^ ((~e) & g)
      temp1 = ((((((((h + S1) & 0xFFFFFFFF) + ch) & 0xFFFFFFFF) + k[i]) & 0xFFFFFFFF) + int(words[i], 2)) & 0xFFFFFFFF)
      wa = (bin(a)[2:].zfill(32))
      rr2 = int(wa[32-2:] + wa[:32-2], 2)       # right rotate 2
      rr13 = int(wa[32-13:] + wa[:32-13], 2)    # right rotate 13
      rr22 = int(wa[32-22:] + wa[:32-22], 2)    # right rotate 22
      S0 = rr2 ^ rr13 ^ rr22
      maj = (a & b) ^ (a & c) ^ (b & c)
      temp2 = ((S0 + maj) & 0xFFFFFFFF)
      h = g
      g = f
      f = e
      e = ((d + temp1) & 0xFFFFFFFF)
      d = c
      c = b
      b = a
      a = ((temp1 + temp2) & 0xFFFFFFFF)

    # after a-b values modification new hash values (h0-h7) are modified their representetive parameter (a-b)
    h0 = ((h0 + a) & 0xFFFFFFFF)
    h1 = ((h1 + b) & 0xFFFFFFFF)
    h2 = ((h2 + c) & 0xFFFFFFFF)
    h3 = ((h3 + d) & 0xFFFFFFFF)
    h4 = ((h4 + e) & 0xFFFFFFFF)
    h5 = ((h5 + f) & 0xFFFFFFFF)
    h6 = ((h6 + g) & 0xFFFFFFFF)
    h7 = ((h7 + h) & 0xFFFFFFFF)


    
  # after all 512-bit part iteration completed SHA256 output can be generated
  # this is performed by string concetenation of modified h0-h7 values 
  # output is hexadecimal format (0x)
  # it can be converted to decimal and binary format
  hash_hexadecimal = hex(h0)[2:].zfill(8) + hex(h1)[2:].zfill(8) + hex(h2)[2:].zfill(8) + hex(h3)[2:].zfill(8) + hex(h4)[2:].zfill(8) + hex(h5)[2:].zfill(8) + hex(h6)[2:].zfill(8) + hex(h7)[2:].zfill(8)


  return "0x" + hash_hexadecimal





def sha256_string_input(input_string:str):
  # it must be encoded to decimal equivalent of UTF-16 format
  # after that, encoded value must be converted to binary value to generate binary array of input_string
  # e.g. 
  # b = 98 = 0b0000000001100010
  # t = 116 = 0b0000000001110100
  # c = 99 = 0b0000000001100011
  # unidentified characters are ignored.
  encoded_input = input_string.encode("utf-16", "ignore")
  input_binary = ""
  for e in encoded_input:
    input_binary += bin(e)[2:].zfill(16)
    # bin() function returns 0b.... value and trims leading zeros if exist
    # '[2:].zfill(16)' is used to format binary string
  return sha256_binary_input(input_binary)









# for base58 encoding
# read: https://learnmeabitcoin.com/technical/base58

base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def hex_to_base58(hex_input: str):
    dec = int(hex_input, 16)
    rt = ""
    while(dec > 0):
        reminder = dec % 58
        dec = dec // 58
        rt = base58[reminder] + rt
    for h in hex_input[2:]:
        if(h == "0"):
            rt = "1" + rt
        else:
            break
    return rt



def hex_to_base58check(hex_input: str):
    
    hex_input = "0x80" + hex_input[2:] + "01" 
    # "0x80" prefix is stand for Private key (WIF, compressed pubkey)
    # see: https://en.bitcoin.it/wiki/List_of_address_prefixes 

    

    # first 4 byte of double hash is used for checksum suffix 
    s1 = sha256_binary_input(bin(int(hex_input, 16))[2:].zfill(256))
    s2 = sha256_binary_input(bin(int(s1, 16))[2:].zfill(256))
    hex_input += s2[2:10]

    return hex_to_base58(hex_input)









readme_text = """!!!!!!!!!!!!!!!!!!!  ATTENTION  !!!!!!!!!!!!!!!!!!!!

To generate private key write a sentence in "SENTENCE.txt" file.
--------------------------------
Use English language characters.
Recomended characters are;
A-Z letters
a-z letters
0,1,2,3,4,5,6,7,8,9 numbers
' (apostrophe)
. (dot)
, (comma)
--------------------------------
At least use 20 characters to ensure strong encryption.
Otherwise if it will be too short, it will be easily predictable.
And your bitcoin would be stolen.

After private key generation completed, write your sentence any paper.

When you wrote your private key (and sentence) to a paper;
Delete "SENTENCE.txt" file and "BITCOIN PRIVATE KEY.txt" file. 
Don't store these files in your computer.
Don't store at e-mail.
Don't store at phone as photograph.
Don't store at cloud services like Google Drive, OneDrive etc.
Don't share your sentence with anyone.
Don't share your private key with anyone.

You can generate public key (bitcoin address) via third party application like Electrum.
https://electrum.org/#home

You can share your public key (bitcoin address), NOT private key (sentence).
Anyone can send you bitcoin to your public key address, not private key (sentence).
So you should share your public key to sender, not private key (sentence).

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"""


file = open("README.txt", "wt")
file.write(readme_text)
file.close()


sentence = ""
is_sentence_wrote = False

try:
    file = open("SENTENCE.txt", "rt")
    is_sentence_wrote = True
    file.close()
except:
    file = open("SENTENCE.txt", "xt")
    file.close()
   

if(is_sentence_wrote):
    
    file = open("SENTENCE.txt", "rt")
    sentence = file.read()

    if(sentence != ""):
        
        sentence = "".join(sentence.split())
        sentence = sentence.lower()

        hex_value = sha256_string_input(sentence)
        b58cc = hex_to_base58check(hex_value)

        output = """
        
        BITCOIN PRIVATE KEY:

          p2wpkh:{}

          

        Do not share this private key with anyone. 
        Just use it in third party bitcoin wallet application like Electrum.
        https://electrum.org/#home

        

        MODIFIED SENTENCE: 
        
        {}
        """.format(b58cc, sentence)

        file = open("BITCOIN PRIVATE KEY.txt", "wt")
        file.write(output)
        file.close()


