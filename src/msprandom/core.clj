(ns msprandom.core
  (:gen-class)
  (:require [msprandom.kbd :as k]
            [msprandom.crypto :as c]
            [clojure.edn :as edn])
  (:import (java.util Arrays)))


(defn- read-edn-file
  "This function reads file in edn format and returns its content as clojure object or nil."
  [filename]
  (edn/read-string (slurp filename)))

(defn update-vault
  "Update a random vault file.
  Updating random data is necessary to avoid usage the same random data twice.
  Returns: updated random data as byte array[64]"
  [^String vname
   ^String passw]
  (let [enc-data (read-edn-file vname)]
    (when enc-data
      (let [{:keys [data]} enc-data
            enc-rand (c/hex-to-bytes data)
            dkey (c/gost-hash (.getBytes passw))            ;generate secret key based on password
            iv (Arrays/copyOfRange ^bytes (c/gost-hash dkey) 0 8) ;generate iv
            d (c/gost-engine dkey iv false)                 ;init gost engine for decryption
            rand-data (c/decrypt d enc-rand)                ;decrypt random data

            nano1 (System/nanoTime)
            str-nano1 (str nano1)
            hash1 (c/gost-hash (.getBytes str-nano1))
            left-hash (c/gost-hash (byte-array (concat rand-data hash1)))

            nano2 (System/nanoTime)
            str-nano2 (str nano2)
            hash2 (c/gost-hash (.getBytes str-nano2))
            right-hash (c/gost-hash (byte-array (concat rand-data hash2)))

            new-rand-data (byte-array (concat left-hash right-hash)) ;produce 64 bytes or 512 bits of strong random data

            ekey (c/gost-hash (.getBytes passw))            ;generate secret key based on password
            iv (Arrays/copyOfRange ^bytes (c/gost-hash ekey) 0 8) ;generate iv
            e (c/gost-engine ekey iv true)                  ;init gost engine for encryption
            enc-data (c/encrypt e new-rand-data)            ;encrypt random data
            hmac (c/passw-hmac passw enc-data)              ;generate hmac based on password
            result (str {:data (c/bytes-to-hex enc-data) :hmac (c/bytes-to-hex hmac)})]
        (spit vname result :append false)
        new-rand-data))))

(defn new-vault
  "Create new file as a vault for random data 512 bits length.
  Vault is encrypted with password and ptotected with HMAC.
  This function works only in console mode.
  Returns: generated random data as byte array[64]"
  [^String vname
   ^String passw]
  (let [rand-count (* 3 64)                                 ;suppose only 3 bits in each byte is true random data
        raw-data (k/kbdrand rand-count)                     ;generate rand-count of raw random bytes
        left-raw (Arrays/copyOfRange ^bytes raw-data (int 0) (int (/ rand-count 2))) ;take first half of raw random data array
        right-raw (Arrays/copyOfRange ^bytes raw-data (int (/ rand-count 2)) (int rand-count)) ;take second half of raw random data array
        left-hash (c/gost-hash left-raw)                    ;generate hash from first half
        right-hash (c/gost-hash right-raw)                  ;generate hash from second half
        rand-data (byte-array (concat left-hash right-hash)) ;produce 64 bytes or 512 bits of strong random data

        ekey (c/gost-hash (.getBytes passw))                ;generate secret key based on password
        iv (Arrays/copyOfRange ^bytes (c/gost-hash ekey) 0 8) ;generate iv
        e (c/gost-engine ekey iv true)                      ;init gost engine for encryption
        enc-data (c/encrypt e rand-data)                    ;encrypt random data
        hmac (c/passw-hmac passw enc-data)                  ;generate hmac based on password
        result (str {:data (c/bytes-to-hex enc-data) :hmac (c/bytes-to-hex hmac)})]
    (spit vname result :append false)
    rand-data))

(defn load-vault
  "Load random data from a vault. Vault is updated automatically to avoid usage the same random data twice.
  Returns: random data as byte array[64]"
  [^String vname
   ^String passw]
  (let [enc-data (read-edn-file vname)]
    (when enc-data
      (let [{:keys [data hmac]} enc-data
            enc-rand (c/hex-to-bytes data)
            new-hmac (c/passw-hmac passw enc-rand)]
        (if (= (c/bytes-to-hex new-hmac) hmac)
          (let [dkey (c/gost-hash (.getBytes passw))        ;generate secret key based on password
                iv (Arrays/copyOfRange ^bytes (c/gost-hash dkey) 0 8) ;generate iv
                d (c/gost-engine dkey iv false)             ;init gost engine for decryption
                rand-data (c/decrypt d enc-rand)            ;decrypt random data
                _ (update-vault vname passw)]
            rand-data)
          (throw (Exception. "Vault is corrupted or wrong password!")))))))

(defn gen-rand
  "Generate secure random bytes using given seed. Seed must be array of true random bytes >= 32 bytes
  Returns: array filled with random bytes or nil."
  [^bytes rand-seed
   ^long n]
  (if rand-seed
    (let [nanosec (System/nanoTime)
          new-rand (byte-array (concat rand-seed (.getBytes (str nanosec))))
          ekey (c/gost-hash new-rand)
          iv (Arrays/copyOfRange ^bytes (.getBytes (str (System/nanoTime))) 0 8) ;generate iv
          e (c/gost-engine ekey iv true)                    ;init gost engine for encryption
          buf (byte-array n)
          enc-data (c/encrypt e buf)                        ;encrypt empty array
          ]
      enc-data)
    (throw (Exception. "Got empty seed."))))
