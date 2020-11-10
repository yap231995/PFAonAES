from src.AES import *
from src.PFA_AES import *
from src.attack import *

### Testing encryption and decrypt function
key_matrix1= [[0x52, 0x09, 0x6A, 0xD5],[0x3A, 0x91, 0x11, 0x41], [0xA7, 0x8D, 0x9D, 0x84],[0x07, 0x12, 0x80, 0xE2]]
Matrix2 = [[0x4A, 0x0D, 0x2D, 0xE5],[0xC9, 0x7D, 0xFA, 0x59], [0xA3, 0x9E, 0x81, 0xF3], [0x02, 0x04, 0x08, 0x10]]
print('plaintext:')
print(Matrix2)
ciphertext = encrypt(Matrix2, key_matrix1)
print('ciphertext:')
print(ciphertext)
decrypted_text = decrypt(ciphertext, key_matrix1)
print('decrypted_text:')
print(decrypted_text)

### Testing PFA encryption
faultinjection()
faulty_text = PFA_encrypt(Matrix2, key_matrix1)
print('faulty_text:')
print(faulty_text)


##Retrieving Unknown value of Fault
CiphertextList = GenerateCiphertext(key_matrix1,800)
freqTable = CountValueOver16Bytes(CiphertextList)
GuessFaultValue = FaultValue(freqTable)
print("GuessFaultValue:" + str(GuessFaultValue))
#TODO: Visualisation of the number of ciphertext needed.



##Retrieving C_min
##TODO: visualsing of the num of ciphertext anmd c_min 
print("C_min matrix:")
C_min = PFA_Maxlikelihood(freqTable, GuessFaultValue)
print(C_min)
## TODO: check PFA Maxlikelihood is it correct
