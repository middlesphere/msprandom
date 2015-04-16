# INTRODUCTION

## A PROBLEM STATEMENT
 
This library demonstrates a technique of generating random numbers for cryptographic purposes without hardware generators. 
Encryption and signing requires a random numbers with good quality. 
Generating a random numbers (or sequences of random bytes) without hardware generators is not
trivial task. Especially this problem is actual for a small devices where sources of random data are absent or limited. 
The solution is to have true random seed saved in a secured file (vault) and cipher which can produce encrypted pseudo random generated
(PRNG) sequences based on random seed with good random characteristics. 

Many cryptographic libraries (e.g. BouncyCastle) use SecureRandom class  for encryption and signing to 
get random numbers. SecureRandom depends on OS implementation. Another words, realization of random engine is outside your 
application which you cannot control. To avoid of using poor random numbers you MUST seed SecureRandom generator with good random 
data every time you call cryptographic functions which requires the random data. Or you can extend SecureRandom class with your realization
that produces a random numbers which quality you can control.

RULE: The strength of any cryptographic system is highly depends on random numbers!

## HOW TO USE:

Some steps how to msprandom inside your application:
1. Generate on your computer or notebook a true random seed  and put it to a vault using this library (function new-vault).
2. Put a vault (file) with random seed  on your device, computer or server where you need to encrypt and sign data.
3. Load the vault once at the start of the program when you need encrypt or sign data (function load-vault).
4. Call gen-rand function from msprandom library to get random bytes as many times as you need.

The vault with random seed is encrypted and secured with HMAC.
Random seed in a vault is updated every time you load vault with unpredictable way, so HMAC is changing too.
Changing a vault is made intentionally against situation if attacker can rich some copy of your vault in the past.

## HOW IT WORKS:

To generate a true random seed a human input is used. Here are the algorithm of collecting a random data:

1. Run separate thread where atomic counter increments every tic from 0..255 with a very high speed.
2. Wait for unbuffered key press by human and get a scan code of pressed button.
3. Take current nanoseconds value from start of Epoch and take mod 256 to convert its value to a random byte.
4. Xor values between each other: scan-code-byte ^ current-counter-value ^ nanoseconds to produce random byte.
5. Add random byte to output vector. We suppose that only 3 bits has true randomness in this random byte. So, to get 
   true random 32 bytes we need ~ 32*3 button press from user input.
6  Repeat steps 2-5 until we get required amount of random bytes. 
7. If we collected required amount of random data then do final step -> hash output vector with cryptographically strong 
   hash function GOST 3411-94 to guarantee that probability 1 and 0 bits in output vector will be 0.5. 
   Note, that hash function used here only to mix random bits and do not influence to the quality of random data. 
   So hash(random data) = random data.


Using this algorithm the msprandom collects a true 512 random bits as a seed which will be saved an a vault. 

Why 512 random bits is enough?

Well, every PRNG needs a true random seed. If an attacker knows a seed then it can predict key generation and so on.
256 bits of initial random seed is far enough to keep millitary grade secrets.
I did 512 to be sure that nobody can brute force or guess the initial random seed.
So, you can freely use msprandom to seed you PRNG or SecureRandom generators.

## USAGE

1. Create new project `lein new app rand-tester`

2. Add to your project.clj the following lines:
```
:dependencies [[com.middlesphere/msprandom "0.5.2"]]

:profiles {
           :dev      {:dependencies [[org.bouncycastle/bcprov-jdk15on "1.52"]]}
           :provided {:dependencies [[org.bouncycastle/bcprov-jdk15on "1.52"]]}}
:manifest {"Class-Path" "bcprov-jdk15on-1.52.jar"}                 
                 
```
 Bouncycastle library should be as a separate jar file, not inside jar. 
 
 
### Create random data vault
 
 Before you can get random numbers with good quality you should create a true random numbers and put them in a vault.
 Here is the code snippet how to create true random numbers and put them to a secured vault.
``` 
 (msprandom.core/new-vault "vault.edn" "StrongPassword12")
```
   
This code should be run in console mode due to unbuffered console input is used to collect random data.
Generated random data 512 bit length is encrypted with given password and HMAC is added to detect any changes.

### Get random data

To get good random data you should:

1. Load true random seed from vault. 

```
(let [  seed (msprandom.core/load-vault "vault.edn" "StrongPassword12")]
    (println (msprandom.crypto/bytes-to-hex seed)))
```

** Warning, call this function only 1 time at the start of the program. **


2. To produce random data call msprandom.core/gen-rand function to get random data based on seed 512 bits length.
This function generates strong random sequence of bytes using PRNG based on GOST28147-89 in CFB mode.
Here is the code snippet how to get 1000 bytes of random data.

```
(let [  seed (msprandom.core/load-vault "vault.edn" "StrongPassword12")
        rand-data (msprandom.core/gen-rand seed 1000)]
    (println (msprandom.crypto/bytes-to-hex rand-data)))
```
You can call msprandom.core/secure-rand as many times as you need.

** After successful reading of random data a random vault is updated to to avoid usage the same random data twice.
Strong cryptography hash function is used to derive new random data.
So, next time  you load  random data from a vault you will get different value of true random seed. **  
 

## License

Copyright © 2015 by Middlepshere.

Distributed under the Eclipse Public License either version 1.0 or any later version.

