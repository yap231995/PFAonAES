from src.PFA_AES import *
from multiprocessing import Pool

def RandomMatrix():
    matrix = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    for i in range(0,4):
        for j in range(0,4):
            matrix[i][j]=random.randint(0, 255)
    return matrix

def GenerateCiphertext(key,numofciphertext, *Table):
    CiphertextList = []
    for num in range(numofciphertext):
        plaintext = RandomMatrix()
        #ciphertext = PFA_encrypt(plaintext, key) #change back to this after debug
        if Table == ():
            ciphertext = PFA_encrypt(plaintext, key)
        else:
            ciphertext = PFA_encrypt(plaintext, key, Table[0])
        CiphertextList.append(ciphertext)
    return CiphertextList

def CountValueOver16Bytes(CiphertextList):
    freqTable = [[0 for l in range(0, 256)] for j in range(0, 16)]
    for ciphertext in CiphertextList:
        for j in range(0,16):
            row = j%4
            col = j//4
            x = ciphertext[col][row]
            freqTable[j][x] += 1
    return freqTable

def FaultValue(freqTable):
    maxprob = 0
    maxtheta = 0
    for theta in range(0, 256):
        prob = 1
        for j in range(0, 16):
            suming = 0
            for l in range(0, 256):
                if freqTable[j][l] == 0:
                    value = l ^ theta
                    suming += 2**freqTable[j][value]
            prob = prob * suming
        if(prob > maxprob):
            maxprob = prob
            maxtheta = theta
    return maxtheta

### Return the c_j^min stated in the paper.
def PFA_Maxlikelihood_single_Byte(freqTable, FaultValue, j):
    maxtheta = 0
    maxprob = 0
    for theta in range(0, 256):
        prob = 0
        if freqTable[j][theta] == 0:
            value = theta ^ FaultValue
            prob = 2**freqTable[j][value]
        ##print(str(theta) + ": prob - "+ str(prob))
        if(maxprob < prob):
            ##print("j:" + str(j) + " "+ str(theta) + ": prob - "+ str(prob))
            maxprob = prob
            maxtheta = theta
    return maxtheta

### Return a matrix C_min
def PFA_Maxlikelihood(freqTable, FaultValue):
    C_min = [[0 for j in range(0,4)] for i in range(0,4)]
    for j in range(0, 16):
        row = j % 4
        col = j // 4
        x = PFA_Maxlikelihood_single_Byte(freqTable, FaultValue, j)
        C_min[col][row] = x
    return C_min

def PossibleKey(SboxIndex, C_min):
    key = [[0 for j in range(0, 4)] for n in range(0, 4)]
    for j in range(0, 16):
        row = j % 4
        col = j // 4
        key[col][row] = C_min[col][row] ^ s_box[SboxIndex]
    return key



def Round9Key_from_Round10Key(key_10):
    k_1 = key_10[0][0]
    k_2 = key_10[0][1]
    k_3 = key_10[0][2]
    k_4 = key_10[0][3]
    k_5 = key_10[1][0]
    k_6 = key_10[1][1]
    k_7 = key_10[1][2]
    k_8 = key_10[1][3]
    k_9 = key_10[2][0]
    k_10 = key_10[2][1]
    k_11 = key_10[2][2]
    k_12 = key_10[2][3]
    k_13 = key_10[3][0]
    k_14 = key_10[3][1]
    k_15 = key_10[3][2]
    k_16 = key_10[3][3]
    key_9 = [[0 for j in range(0, 4)] for i in range(0,4)]
    key_9[0][0] = k_1^s_box[k_14^k_10]^r_con[10]
    key_9[0][1] = k_2 ^ s_box[k_15 ^ k_11]
    key_9[0][2] = k_3 ^ s_box[k_16 ^ k_12]
    key_9[0][3] = k_4 ^ s_box[k_13 ^ k_9]

    key_9[1][0] = k_5 ^ k_1
    key_9[1][1] = k_6 ^ k_2
    key_9[1][2] = k_7 ^ k_3
    key_9[1][3] = k_8 ^ k_4

    key_9[2][0] = k_9 ^ k_5
    key_9[2][1] = k_10 ^ k_6
    key_9[2][2] = k_11 ^ k_7
    key_9[2][3] = k_12 ^ k_8

    key_9[3][0] = k_13 ^ k_9
    key_9[3][1] = k_14 ^ k_10
    key_9[3][2] = k_15 ^ k_11
    key_9[3][3] = k_16 ^ k_12

    return key_9


def PenultimateSboxOutput(matrix1, key_10):
    matrix = [[0 for j in range(0, 4)] for i in range(0,4)]
    for j in range(0, 4):
        for i in range(0, 4):
            matrix[j][i] = matrix1[j][i] ^ key_10[j][i] #addkeys
    ##print("before subbyte")
    ##print(matrix)
    inv_shiftrow(matrix)
    inv_subbytes(matrix)
    key_9 = Round9Key_from_Round10Key(key_10)
    add_key(matrix, key_9)
    inv_mix_column(matrix)
    inv_shiftrow(matrix)
    return matrix