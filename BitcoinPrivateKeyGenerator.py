# Python version: 3.11.0 (64-bit, x64)
# Updated: 07/04/2023
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
# for ecdsa:
# https://learnmeabitcoin.com/technical/ecdsa#key-generation
# for base58 encoding:
# read: https://learnmeabitcoin.com/technical/base58


# for RIPEMD-160 :
# https://en.bitcoin.it/wiki/List_of_address_prefixes
# https://en.bitcoin.it/wiki/Wallet_import_format
# https://learnmeabitcoin.com/technical/base58#modulus
# https://learnmeabitcoin.com/technical/wif
# https://learnmeabitcoin.com/technical/public-key
# https://learnmeabitcoin.com/technical/public-key-hash
# https://learnmeabitcoin.com/technical/address
# https://github.com/toddr/Crypt-RIPEMD160/tree/master/rmd160/hash
# https://github.com/toddr/Crypt-RIPEMD160/blob/master/rmd160/hash/rmd160.h
# https://github.com/toddr/Crypt-RIPEMD160/blob/master/rmd160/hash/rmd160.c
# https://homes.esat.kuleuven.be/~bosselae/ripemd/rmd160.txt
# https://homes.esat.kuleuven.be/~bosselae/ripemd160.html#Outline



# Online Bech32 / SegWit address generation:
# *1 https://learnmeabitcoin.com/technical/hash-function#hash160
# *2 https://slowli.github.io/bech32-buffer/
# First, copy the "public key (compressed)" to *1 website to generate output of Hash160 (ripemd160(sha256())).
# After, copy the "output of Hash160" to *2 website to generate Bech32 / SegWit address. (params: mainnet, scriptver 0)


"""
TODO: RIPEMD-160 hashing algorithm is not implemented yet.
"""





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










# for ecdsa:
# https://learnmeabitcoin.com/technical/ecdsa#key-generation

class POINT:
    x = int(0)
    y = int(0)
    def __init__(self, x=0, y=0):
        self.x = x
        self.y = y
    def __str__(self):
        return "\n" + f"x: {self.x}" + "\n" + f"y: {self.y}"
    

class SIGNATURE:
    r = int(0)
    s = int(0)
    def __init__(self, r=0, s=0):
        self.r = r
        self.s = s
    def __str__(self):
        return "\n" + f"r: {self.r}" + "\n" + f"s: {self.s}"
    
# secp256k1
# y² = x³ + ax + b   # a = 0   # b = 7

# prime field
p = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1

# number of points on the curve we can hit ("order")
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

# generator point (the starting point on the curve used for all calculations)
G = POINT(55066263022277343669578718895168534326250603453777594175500187360389116729240,
          32670510020758816978083085130507043184471273380659243275938904335757337482424)


def inverse(a, m):
    # store original modulus
    m_orig = m          

    # make sure a is positive
    if (a < 0):         
        a = a % m 

    prevy, y = 0, 1

    while (a > 1):
        q = m // a
        y, prevy = prevy - q * y, y
        a, m = m % a, a

    return y % m_orig


def double(point):
    # slope = (3x₁² + a) / 2y₁
    # using inverse to help with division
    slope = ((3 * point.x ** 2 + 0) * inverse((2 * point.y), p)) % p 

    # x = slope² - 2x₁
    x = (slope ** 2 - (2 * point.x)) % p

    # y = slope * (x₁ - x) - y₁
    y = (slope * (point.x - x) - point.y) % p

    return POINT(x,y)



def add(point1, point2):
    # double if both points are the same
    if (point1 == point2):
        return double(point1)
    
    # slope = (y₁ - y₂) / (x₁ - x₂)
    slope = ((point1.y - point2.y) * inverse(point1.x - point2.x, p)) % p

    # x = slope² - x₁ - x₂
    x = (slope ** 2 - point1.x - point2.x) % p

    # y = slope * (x₁ - x) - y₁
    y = ((slope * (point1.x - x)) - point1.y) % p

    return POINT(x,y)



def multiply(k, point):
    # create a copy the initial starting point (for use in addition later on)
    current = point

    # convert integer to binary representation
    binary = bin(k)[3:]

    # double and add algorithm for fast multiplication
    #index = 0
    for b in binary:
        current = double(current)
        if(b == "1"):
            current = add(current, point)
        #print("i: {}\t{}{}".format(index, b, current))
        #index += 1
        
    return current








# for base58 encoding
# read: https://learnmeabitcoin.com/technical/base58

base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def hex0x_to_base58(hex_input: str):
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



def hex0x_to_base58check(hex_input: str):
    hex_input = "0x80" + hex_input[2:] + "01" 
    # "0x80" prefix is stand for Private key (WIF, compressed pubkey)
    # see: https://en.bitcoin.it/wiki/List_of_address_prefixes 

    # first 4 byte of double hash is used for checksum suffix 
    s1 = sha256_binary_input(bin(int(hex_input, 16))[2:].zfill(256))
    s2 = sha256_binary_input(bin(int(s1, 16))[2:].zfill(256))
    hex_input += s2[2:10]

    return hex0x_to_base58(hex_input)



def generate_base58cc_private_key_from_text_input(t:str):
    h = sha256_string_input(t)
    bc = hex0x_to_base58check(h)
    d = int(h, 16)
    return(bc, h, d)



def generate_public_keys_from_private_key(pik:int):
    puk =  multiply(pik, G)
    # convert x and y values of this point to hexadecimal
    x = hex(puk.x)[2:].rjust(64, "0")
    y = hex(puk.y)[2:].rjust(64, "0")
    # uncompressed public key format (not used much these days)
    puk_u = "04" + x + y
    puk_c = x
    if(puk.y % 2 == 0):
        puk_c = "02" + puk_c
    else:
        puk_c = "03" + puk_c
    return (puk_u, puk_c)







# abrevated_auxiliary_verbs = {
#     "i'm" : "iam",
#     "he's" : "heis"
#     ...
# }
# 
# TODO
# convert abrevated auxiliary verbs to long forms to eliminate typo

def modify_text(text_input:str):
    #text = "".join(text.split())
    text_input = text_input.replace("\n", "")
    text_input = text_input.replace("\t", "")
    text_input = text_input.lower()
    text_input = text_input.replace(" ", "")
    text_input = text_input.replace("'", "")
    text_input = text_input.replace(",", "")
    text_input = text_input.replace(".", "")
    return text_input

   




character_use_count = {"0":0,"1":0,"2":0,"3":0,"4":0,"5":0,"6":0,"7":0,"8":0,"9":0,"a":0,"b":0,"c":0,"d":0,"e":0,"f":0,"g":0,"h":0,"i":0,"j":0,"k":0,"l":0,"m":0,"n":0,"o":0,"p":0,"q":0,"r":0,"s":0,"t":0,"u":0,"v":0,"w":0,"x":0,"y":0,"z":0,"A":0,"B":0,"C":0,"D":0,"E":0,"F":0,"G":0,"H":0,"I":0,"J":0,"K":0,"L":0,"M":0,"N":0,"O":0,"P":0,"Q":0,"R":0,"S":0,"T":0,"U":0,"V":0,"W":0,"X":0,"Y":0,"Z":0,"'":0,",":0,".":0}
valid_characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',."
def check_input_text_is_valid(text_input:str):
    characters_length = len(text_input)
    if(len(text_input) < 20):
        return (False, 1)
    for t in text_input:
        is_valid_char = False
        for a in valid_characters:
            if(t == a):
                is_valid_char = True
                character_use_count[a] += 1
                break
        if(is_valid_char == False):
            return (False, 2)
    for u in character_use_count:
        use_count = character_use_count[u]
        if(use_count / characters_length > float(0.33)): # input text will be rejceted if any character is used mor than %33 percentage of sentences
            return (False, 3)
    return (True, 0)

 





readme_text = """
Write one or more sentences in "TEXT_INPUT.txt" file to generate private key .


    At least use 20 characters except spaces.
--> It is recommended to write minimum 40 characters except spaces to ensure strong encryption.
    If you use too short sentences, it will be easy to predict your private key and your bitcoin could be stolen.


Use below characters. Other characters are not valid.
-----------------------------------------------------
  A-Z English letters
  a-z English letters
  0,1,2,3,4,5,6,7,8,9 numbers
  . (dot)
  , (comma)
  ' (apostrophe) [not advised]
-----------------------------------------------------

" '(apostrophe) " may cause typo. It is not adviced to use.
If you forget you used the abrevated auxiliary verbs, you can't generate correct private key from your wrong sentences.


After private key generation completed, write your sentences any paper.

When you wrote your private key (and sentences) to a paper;
Delete "TEXT_INPUT.txt" file.
Delete "BITCOIN KEYS.txt" file.
Empty your recycling bin.
Don't store "TEXT_INPUT.txt" and "BITCOIN KEYS.txt" files in your computer.
Don't store this files and private key at e-mail.
Don't store this files and private key at phone as photograph.
Don't store this files and private key at cloud services like Google Drive, OneDrive etc.
Don't share this files and private key with anyone.

You can share your public key (bitcoin address), not private key (sentences).
Anyone can send you bitcoin to your public key address, not to private key (sentences).

"""



def format_bitcoin_keys_text(private_key:str, public_key_compressed:str):
    return """
    
    BITCOIN KEYS:


    
    Private key  -----------------------------------------> {}

    This is your private key. It is secret to you. 
    Write this key to paper and store it securely.
    Do not share this private key with anyone.
    Do not write website or online tools. 
    If anyone learn this private key, he/she can stole your bitcoin.
    Just use it in third party bitcoin wallet application like Electrum.
    https://electrum.org/#home
    https://bitcoin.org/en/choose-your-wallet
    *If you want use SegWit / Bech32 address format add "p2wpkh:" prefix to private key.

    


    

    Public key (compressed) ------------------------------> {}

    This is yours public key. You can share this key. 
    If you want other people to send you bitcoin, you should share this public key.

    




    SegWit / Bech32 address:

    This address is new type of bitcoin address. 
    It starts with "bc1" prefix.
    Its use is optional but it is recommended to use.
    Most people use segwit/bech32 address today.
    It is generated from public key.
    You can generate it from online tools. Explained below:
    *1 https://learnmeabitcoin.com/technical/hash-function#hash160
    *2 https://slowli.github.io/bech32-buffer/
    First, copy the "public key (compressed)" to *1 website to generate output of Hash160 (ripemd160(sha256())).
    After, copy the "output of Hash160" to *2 website to generate Bech32 / SegWit address. (params: mainnet, scriptver 0)

    """.format(private_key, public_key_compressed)






file = open("README.txt", "wt")
file.write(readme_text)
file.close()


text = ""
is_sentence_wrote = False

try:
    file = open("TEXT_INPUT.txt", "rt")
    is_sentence_wrote = True
    file.close()
except:
    file = open("TEXT_INPUT.txt", "xt")
    file.close()
   







if(is_sentence_wrote):
    
    file = open("TEXT_INPUT.txt", "rt")
    text = file.read()

    if(text != ""):
            
        text = modify_text(text)

        (is_text_valid, rejection_code) = check_input_text_is_valid(text)

        if(is_text_valid):
        
            (private_key, hex_value, decimal_value) = generate_base58cc_private_key_from_text_input(text)

            (public_key_uncompressed, public_key_compressed) = generate_public_keys_from_private_key(decimal_value)

            sha256_of_public_key_compressed = sha256_string_input(public_key_compressed)

            bitcoin_keys_text = format_bitcoin_keys_text(private_key, public_key_compressed)

            file = open("BITCOIN KEYS.txt", "wt")
            file.write(bitcoin_keys_text)
            file.close()

        else:
            file = open("BITCOIN KEYS.txt", "wt")
            ft = ""
            if(rejection_code == 1):
                ft = "Please write enough characters. \n\nWrite at least 20 characters except spaces. \n\nSee \"README.txt\" file for more info."
            elif(rejection_code == 2):
                ft = "Please write valid characters. \n\nSee \"README.txt\" file for more info."
            elif(rejection_code == 3):
                ft = "Please write heterogeneous sentences. \n\nDo not use any letters too frequently. \n\nAny character frequency must be less than %33 percent. \n\nOtherwise your private can be easily predictable and your Bitcoins could be stolen. \n\nSee \"README.txt\" file for more info."
            else:
                ft = "Unidentified error occured at processing text inside \"TEXT_INPUT.txt\" file. \n\nPlease try another sentences. \n\nSee \"README.txt\" file for more info."
            file.write(ft)
            file.close()

    else:
        file = open("BITCOIN KEYS.txt", "wt")
        file.write("Write any sentences inside \"TEXT_INPUT.txt\" file to generate Bitcoin keys.")
        file.close()

