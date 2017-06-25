# -*- coding: utf-8 -*-

# RSA encryption - decryption implementation

# Based on:
# http://www.pagedon.com/rsa-explained-simply/my_programming/
# http://southernpacificreview.com/2014/01/06/rsa-key-generation-example/
# https://0day.work/how-i-recovered-your-private-key-or-why-small-keys-are-bad/

import fractions
import base64
import sympy

class Math():
    
    @staticmethod    
    def primeFactors(n):
        
        factors = []
        
        for i in range(2, n):
            if n % i == 0:
                factors.append(i)

        return factors

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
    def generateKeysRSA(p, q):
    
        print("\nGenerating Key Pair...\n")
    
        n = p * q
    
        print("p, q: " + str(p) + ", " +  str(q))
        print("n: " + str(n))
    
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

class CrackerRSA():
    
    @staticmethod
    def generateKeysFromKey(key):
        
        print("\n--- Factoring N ---\n")
        
        n = key.n
        
        primeFactors = Math.primeFactors(n)
        
        print("Got n from key: " + str(n))
        
        print("Prime factors: " + str(primeFactors))

        print("Generating Key Pairs...")
        
        KeyGenerator.generateKeysRSA(primeFactors[0], primeFactors[1])
        KeyGenerator.generateKeysRSA(primeFactors[1], primeFactors[0])
        
        print("\n--- Keys Generation Ends ---\n")
        

class TestCase():
    
    @staticmethod
    def testKeysRSA():
        
        print("--- Sanity Checks ---")
        
        keychainA = KeyGenerator.generateKeysRSA(11, 13)
        keychainB = KeyGenerator.generateKeysRSA(29, 31)
        
        result = True
        
        if keychainA.publicKey.a != 7 or keychainA.privateKey.n != 143 or keychainA.privateKey.a != 103 or keychainA.privateKey.n != 143:
            
            result = False
        
        if keychainB.publicKey.a != 11 or keychainB.publicKey.n != 899 or keychainB.privateKey.a != 611 or keychainB.privateKey.n != 899:
            
            result = False
        
        if result != True:
        
            print("RSA Generation Algorithm Is Broken...")
        
            exit(1)
            
        print("\n--- Looks Good! ---")
    
    @staticmethod
    def testTextProcessing(message, keychain):
    
        print("\nEncrypt Raw Message: " + message +"\n")
    
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
        
        print("        Raw: " + str(originalByteArray))
        print("  Encrypted: " + str(encryptedBytes)) 
        print("  Decrypted: " + str(decryptedBytes))
        
        print("\nDecoded Message: " + decodedMessage + "\n")
           
def main(): 

    TestCase.testKeysRSA()

    p = 1
    q = 1
    
    while p == q or p == 1 or q == 1:

        p = sympy.randprime(2, 100)
        q = sympy.randprime(2, 1000)
    
    keychain = KeyGenerator.generateKeysRSA(p, q)
    
    TestCase.testTextProcessing(u"Hello RSA! Привет РСА!", keychain)

    print("\n--- Demo Hack Generate Key Pair Only From Public Key ---\n")
    
    CrackerRSA.generateKeysFromKey(keychain.publicKey)
    
main()
