#Encryption

from Crypto.Cipher import AES
import hashlib

password = "secretpassword".encode()
key = hashlib.sha256 (password).digest()

mode = AES.MODE_CBC
IV =  'This is an IV256'

def pad_message():
    while len (message) % 16 != 0:
    message = message  + " "
    return message

cipher = AES.new(key, mode, IV)

message = "This message should be encrypted "
padded_message = pad_message (message)

encrypted_message = cipher.encrypt (padded_message)

print (encrypted_message)


 # Decryption
from Crypto.Cipher import AES
import hashlib

password =  b'secretpassword'
key = hashlib.sha256 (password).digest()
mode = AES.MODE_CBC
IV = 'This is an IV256'

cipher = AES.new (key, mode, IV)

decrypted_text = cipher.decrypt (encrypted_message)

print (decrypted_text.rstrip().decode())







# I also tried implementing various AES functions. However, the above code did Encrypt and Decrypt using AES, so it was a success.
# NOTE: This is just some extra work I was doing, though I'm still working on it to see if I can implement AES from scratch.
#KeyExpansion
def key_expansion (key):
    key_symbols = [ord (symbol) for symbol in key]
        for i in range (4*Nk - len (key_symbols)):
            key_symbols.append (0*01)
    key_schedule = [ [ ] for i in range (4)]
    for r in range (4):
     for c in range (Nk):
        key_schedule [r].append (key_symbols [r + 4*c])
        tmp = [key_schedule [row] [col-1] for row in range (1,4) ]
        tmp.append (key_schedule [0] [col-1])
             sbox_row = tmp[j] // 0x10
            sbox_col = tmp[j] % 0x10
            sbox_elem =  sbox[16*sbox_row + sbox_col]
            tmp[j] = sbox_elem
            s = key_schedule[row][col - 4]^tmp[row]^rcon[row][col/nk - 1]
                key_schedule[row].append(s)
        else:
                s = key_schedule[row][col - 4]^key_schedule[row][col - 1]
                key_schedule[row].append(s)
    return key_schedule
    
#SubBytes
def sub_bytes (state, inv=False):if inv == False: 
        box = sbox
    else:   
        box = inv_sbox
    for i in range(len(state)):
        for j in range(len(state [i])):
            row = state[i] [j] // 0x10
            col = state[i] [j] % 0x10
            box_elem = box[16*row + col]
            state[i] [j] = box_elem
    return state

#ShiftRows
def shift_rows(state, inv=False):
    count = 1if inv == False:
            state[i] =  left_shift(state[i], count)
            count += 1else: 
            state[i] =  right_shift(state[i], count)
            count += 1
    return state

#MixColumns

def mix_columns(state, inv=False):for i in range(Nb):
        if inv == False: 
            s0 = mul_by_02(state[0][i])^mul_by_03(state[1][i])^state[2][i]^state[3][i]
            s1 = state[0][i]^mul_by_02(state[1][i])^mul_by_03(state[2][i])^state[3][i]
            s2 = state[0][i]^state[1][i]^mul_by_02(state[2][i])^mul_by_03(state[3][i])
            s3 = mul_by_03(state[0][i])^state[1][i]^state[2][i]^mul_by_02(state[3][i])
        else: 
            s0 = mul_by_0e(state[0][i])^mul_by_0b(state[1][i])^mul_by_0d(state[2][i])^mul_by_09(state[3][i])
            s1 = mul_by_09(state[0][i])^mul_by_0e(state[1][i])^mul_by_0b(state[2][i])^mul_by_0d(state[3][i])
            s2 = mul_by_0d(state[0][i])^mul_by_09(state[1][i])^mul_by_0e(state[2][i])^mul_by_0b(state[3][i])
            s3 = mul_by_0b(state[0][i])^mul_by_0d(state[1][i])^mul_by_09(state[2][i])^mul_by_0e(state[3][i])
        state[0][i] = s0
        state[1][i] = s1
        state[2][i] = s2
        state[3][i] = s3
    return state

#AddRoundKey
def add_round_key(state, key_schedule, round=0): for col in range (Nk):
        s0 = state[0][col]^key_schedule[0][Nb * round + col]
        s1 = state[1][col]^key_schedule[1][Nb * round + col]
        s2 = state[2][col]^key_schedule[2][Nb * round + col]
        s3 = state[3][col]^key_schedule[3][Nb * round + col]
        state[0][col] = s0
        state[1][col] = s1
        state[2][col] = s2
        state[3][col] = s3
    return state




#Encryption
def encrypt (input_bytes, key):
    state = [ [ ] for j in range (4) ]
    for r in range (4):
        for c in range (Nb):
            state [r].append (input_bytes [ r + 4*c] )
    key_schedule = key_expansion (key)
    state = add_round_key (state, key_schedule)
    for rnd in range (1, Nr):
        state = sub_bytes (state)
        state = shift_rows (state)
        state = mix_columns (state)
        state = add_round_key(state, key_schedule, rnd)
    state = sub_bytes (state)
    state = shift_rows (state)
    state = add_round_key (state, key_schedule, rnd + 1)
    output = [ None for i in range (4*Nb)]
    for r in range (4):
        for c in range (Nb):
            output [r + 4*c] = state [r][c]
    return output
    
    
#Decrypytion
def decrypt(cipher, key):
    state = [[] for i in range(Nb)]
    for r in range(4):
        for c in range(Nb):
            state[r].append(cipher[r + 4*c])
    key_schedule = key_expansion(key)
    state = add_round_key(state, key_schedule, Nr)
    rnd = Nr - 1while rnd >= 1:
        state = shift_rows(state, inv=True)
        state = sub_bytes(state, inv=True)
        state = add_round_key(state, key_schedule, rnd)
        state = mix_columns(state, inv=True)
        rnd -= 1
    state = shift_rows(state, inv=True)
    state = sub_bytes(state, inv=True)
    state = add_round_key(state, key_schedule, rnd)
    output = [None for i in range(4*Nb)]
    for r in range(4):
        for c in range(Nb):
            output[r + 4*c] = state[r][c]
    return output
