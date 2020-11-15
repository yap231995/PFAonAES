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
print()
### Testing PFA encryption

faultyChangedValue, faultySboxInt = faultinjection()
print("faultySboxInt: " + str(faultySboxInt))
print("faultyChangedValue: " + str(faultyChangedValue))
print("original faultvalue: " +str(s_box[faultySboxInt]^faultyChangedValue))
faulty_text = PFA_encrypt(Matrix2, key_matrix1)
print('faulty_text:')
print(faulty_text)
print()

##Retrieving Unknown value of Fault
CiphertextList = GenerateCiphertext(key_matrix1,2000)
freqTable = CountValueOver16Bytes(CiphertextList)
GuessFaultValue = FaultValue(freqTable)
print("GuessFaultValue:" + str(GuessFaultValue))
#TODO: Visualisation of the number of ciphertext needed.



##Retrieving C_min
##TODO: visualsing of the num of ciphertext anmd c_min
C_min = PFA_Maxlikelihood(freqTable, GuessFaultValue)
print("C_min matrix:")
print(C_min)
##check PFA Maxlikelihood is it correct
W = create_keys(key_matrix1)
k_10 = [W[40],W[41],W[42],W[43]]
CorrectC_min = [[0 for j in range(0, 4)] for i in range(0, 4)]
print("Correct C_min:")
for j in range(0, 16):
    row = j % 4
    col = j // 4
    CorrectC_min[col][row] = k_10[col][row] ^ s_box[faultySboxInt]
print(CorrectC_min)


print()


#TODO: Retriving key
NumofPossibleKey =0
for h in range(0,256):
    key = [[0 for j in range(0, 4)] for n in range(0, 4)]
    for j in range(0, 16):
        row = j % 4
        col = j // 4
        key[col][row] = C_min[col][row] ^ s_box[h]
    Table = [0 for l in range(0,256)]
    for ciphertext in CiphertextList:
        y = FlattenXorSqMatrix(ciphertext, key)
        for j in range(0, len(y)):
            Table[y[j]] = 1
    TotalNumDifferentValue = 0
    print(Table)
    for m in range(0,256):
        TotalNumDifferentValue += Table[m]
    print("TotalNumDifferentValue: "+ str(TotalNumDifferentValue))
    if TotalNumDifferentValue == 256: ## Wrong key
        continue
    else:
        NumofPossibleKey +=1
        ##print("Possible Key:")
        ##print(key)
        ##print()

print(NumofPossibleKey)
print("Original Round 10 key:")
print(k_10)

