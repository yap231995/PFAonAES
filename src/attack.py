from src.PFA_AES import *
from multiprocessing import Pool

def RandomMatrix():
    matrix = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    for i in range(0,4):
        for j in range(0,4):
            matrix[i][j]=random.randint(0, 255)
    return matrix

def GenerateCiphertext(key,numofciphertext):
    CiphertextList = []
    for num in range(numofciphertext):
        plaintext = RandomMatrix()
        ciphertext = PFA_encrypt(plaintext, key)
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
        if(maxprob < prob):
            maxprob = prob
            maxtheta = theta
    return maxtheta

### Return a matrix C_min
def PFA_Maxlikelihood(freqTable, FaultValue):
    C_min = [[0 for j in range(0,4)] for i in range(0,4)]
    for j in range(0,16):
        row = j % 4
        col = j // 4
        x = PFA_Maxlikelihood_single_Byte(freqTable,FaultValue, j)
        C_min[col][row] = x
    return C_min
