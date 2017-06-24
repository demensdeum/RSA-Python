# -*- coding: utf-8 -*-

import fractions
import base64
import sympy

class Math():

    @staticmethod
    def xgcd(b, n):
        
        x0, x1, y0, y1 = 1, 0, 0, 1
        while n != 0:
            q, b, n = b // n, n, b % n
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return  b, x0, y0

    @staticmethod
    def getCoprime(t):
        
        for i in range(2,10000):
            
            if fractions.gcd(i,t) == 1:
                
                return i  
             
    @staticmethod           
    def mulinv(b, n):
        
        g, x, _ = Math.xgcd(b, n)
        if g == 1:
            return x % n 

class KeyRSA():
    
    n = 0
    a = 0
    
    def __init__(self, n, a):
        
        self.n = n
        self.a = a

class KeychainRSA():
    
    publicKey = KeyRSA(0, 0)
    privateKey = KeyRSA(0, 0)
    
    def __init__(self, publicKey, privateKey):
        
        self.privateKey = privateKey
        self.publicKey = publicKey

class KeyGenerator():

    @staticmethod
    def getKeysRSA(p, q):
    
        n = p * q
    
        t = (p - 1) * (q - 1)
    
        e = Math.getCoprime(t)
    
        d = Math.mulinv(e, t)
        
        publicKey = KeyRSA(n, e)
        privateKey = KeyRSA(n, d)
        
        keychain = KeychainRSA(publicKey, privateKey)
        
        return keychain

class ProcessorRSA():

    @staticmethod
    def processBytes(bytesArray, key):
    
        processedBytes = []
    
        for byte in bytesArray:
            
            processedByte = int(byte ** key.a % key.n)
            
            processedBytes.append(processedByte)
            
        return processedBytes

class TestCase():
    
    @staticmethod
    def testKeysRSA():
        
        keychainA = KeyGenerator.getKeysRSA(11, 13)
        keychainB = KeyGenerator.getKeysRSA(29, 31)
        
        result = True
        
        if keychainA.publicKey.a != 7 or keychainA.privateKey.n != 143 or keychainA.privateKey.a != 103 or keychainA.privateKey.n != 143:
            
            result = False
        
        if keychainB.publicKey.a != 11 or keychainB.publicKey.n != 899 or keychainB.privateKey.a != 611 or keychainB.privateKey.n != 899:
            
            result = False
        
        if result != True:
        
            print("RSA Generation Algorithm Is Broken...")
        
            exit(1)
    
    @staticmethod
    def testTextProcessing(message, p, q):
    
        keychain = KeyGenerator.getKeysRSA(p, q)
    
        rawMessage = bytearray(message, 'utf-8')
        encodedMessage = base64.b64encode(rawMessage, None)
        byteArray = bytearray(encodedMessage)
    
        encryptedBytes = ProcessorRSA.processBytes(byteArray, keychain.publicKey)
        decryptedBytes = ProcessorRSA.processBytes(encryptedBytes, keychain.privateKey)
        
        decryptedMessage = str(bytearray(decryptedBytes))
        decodedMessage = base64.b64decode(decryptedMessage)
        
        # Debug Print
        
        originalByteArray = []
        
        for byte in byteArray:
            originalByteArray.append(byte)
    
        print("p:" + str(p))
        print("q:" + str(q)) 
        
        print(originalByteArray)
        print(encryptedBytes) 
        print(decryptedBytes)
        
        print("Decoded Message: " + decodedMessage)
           
def main(): 

    p = sympy.randprime(2, 100)
    q = sympy.randprime(2, 100)
    
    TestCase.testKeysRSA()
    TestCase.testTextProcessing(u"Hello RSA! Привет РСА!", p , q)
    
main()
