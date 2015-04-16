(ns msprandom.crypto
  (:gen-class)
  (:import (org.bouncycastle.util.encoders Hex)
           (org.bouncycastle.crypto.digests GOST3411Digest)
           (org.bouncycastle.jce.provider BouncyCastleProvider)
           (java.security Security)
           (org.bouncycastle.crypto.macs HMac)
           (org.bouncycastle.crypto.params KeyParameter)
           (org.bouncycastle.crypto.generators PKCS5S1ParametersGenerator)
           (javax.crypto.spec SecretKeySpec IvParameterSpec)
           (javax.crypto Cipher CipherOutputStream CipherInputStream)
           (java.io ByteArrayOutputStream ByteArrayInputStream DataInputStream)))

(defn break-jce-policy-limit
  "Break JCE crypto limit. Should be run once, primarily at the begining of the program
  to avoid JCE policy limit if JDK/JRE runtime has no installed files for break crypto limit. Returns nil."
  []
  (let [field (-> (Class/forName "javax.crypto.JceSecurity")
                  (.getDeclaredField "isRestricted"))]
    (.setAccessible field true)
    (.set field nil Boolean/FALSE)))

(defn gost-engine
  "Init GOST 28147-89 engine in CFB mode with given key (byte[32) and iv (byte[8]).
  enc-mode = true for encryption and false for decryption.
  Returns: initialized encryptor ^Cipher object."
  [^bytes k
   ^bytes iv
   ^Boolean enc-mode?]
  (break-jce-policy-limit)
  (let [sk (SecretKeySpec. k "GOST28147")
        cipher (Cipher/getInstance "GOST28147/CFB8/NoPadding" "BC")]
    (if enc-mode?
      (.init cipher Cipher/ENCRYPT_MODE sk (IvParameterSpec. iv))
      (.init cipher Cipher/DECRYPT_MODE sk (IvParameterSpec. iv)))
    cipher))

(defn encrypt
  "Encrypt input byte array of plain text using given cipher engine.
  Return: byte array with encrypted data (== length of input array)."
  [^Cipher c
   ^bytes plain-text]
  (let [bOut (ByteArrayOutputStream.)
        cOut (CipherOutputStream. bOut c)
        _ (.write cOut plain-text 0 (alength plain-text))
        _ (.close cOut)]
    (.toByteArray bOut)))

(defn decrypt
  "Decrypt input byte array using given cipher engine.
   Return: byte array with plain text (== length of input array)."
  [^Cipher c
   ^bytes cipher-text]
  (let [decrypted-data-array (byte-array (alength cipher-text))
        bIn (ByteArrayInputStream. cipher-text)
        cIn (CipherInputStream. bIn c)
        dIn (DataInputStream. cIn)
        _ (.readFully dIn decrypted-data-array)
        _ (.close bIn)]
    decrypted-data-array))

(defn gost-hash
  "Calculate hash from data (byte array) using algorithm GOST3411-94.
  Retrun: hash vector (bytes[32])"
  [^bytes data]
  (break-jce-policy-limit)
  (Security/addProvider (BouncyCastleProvider.))
  (let [digest (GOST3411Digest.)
        _ (.update digest data 0 (alength data))
        hash-buffer (byte-array (.getDigestSize digest))
        _ (.doFinal digest hash-buffer 0)]
    hash-buffer))

(defn hmac
  "Calculate HMAC from data (byte array) using algorithm GOST3411-94 and given seed (byte[32]).
  Retrun: hmac vector (bytes[32])"
  [^bytes seed
   ^bytes data]
  (break-jce-policy-limit)
  (let [hmac-fn (HMac. (GOST3411Digest.))
        key-param (KeyParameter. seed)
        _ (.init hmac-fn key-param)
        _ (.update hmac-fn data 0 (alength data))
        hmac-byte-array (byte-array (.getMacSize hmac-fn))
        _ (.doFinal hmac-fn hmac-byte-array 0)]
    hmac-byte-array))

(defn passw-hmac
  "Calculate HMAC from data (byte array) using algorithm GOST3411-94 and given password (String).
  Retrun: hmac vector (bytes[32])"
  [^String seed
   ^bytes data]
  (hmac (PKCS5S1ParametersGenerator/PKCS5PasswordToUTF8Bytes (.toCharArray seed)) data))

(defn hex-to-bytes
  "Convert String with hex data to byte array.
  Return: byte array"
  [^String s]
  (Hex/decode s))

(defn bytes-to-hex
  "Convert byte array to hex representation.
  Return: String with hex data."
  [^bytes b]
  (Hex/toHexString b))
