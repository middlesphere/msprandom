(ns msprandom.crypto-test
  (:require [clojure.test :refer :all]
            [msprandom.crypto :as c]))

(def etalon-string1 "Suppose the original message has length = 50 bytes")
(def etalon-string2 "This is message, length=32 bytes")
(def etalon-hash1 "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011")
(def etalon-hash2 "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb")
(def etalon-hmac1 "f5c2a4f3ed90550b6be973dc905a601faac9345abb43b399240283802887a548")
(def etalon-hmac2 "b07b86a75eaf84eccf29acae2371ffd35c39b1f21283776f1d492b98c85769fe")
(def etalon-cipher-text "c6361f934e0c496d1db4a1388aeaa121f8cdf2f11208e9a34fcb3f370708a137aee5770f9cb94d5354ebef3d9074b6014816")

(deftest hash-test
  (testing "test hash function."
    (let [h1 (c/gost-hash (.getBytes ^String etalon-string1))
          hs1 (c/bytes-to-hex h1)
          h2 (c/gost-hash (.getBytes ^String etalon-string2))
          hs2 (c/bytes-to-hex h2)]
      (is (= etalon-hash1 hs1))
      (is (= etalon-hash2 hs2)))))

(deftest hmac-test
  (testing "test hmac function"
    (let [seed (c/hex-to-bytes etalon-hash1)
          hm1 (c/hmac seed (.getBytes ^String etalon-string1))
          hms1 (c/bytes-to-hex hm1)]
      (is (= etalon-hmac1 hms1)))))

(deftest passw-hmac-test
  (testing "test passw-hmac function"
    (let [hm2 (c/passw-hmac "Secret" (.getBytes ^String etalon-string1))
          hms2 (c/bytes-to-hex hm2)]
      (is (= etalon-hmac2 hms2)))))

(deftest encrypt-test
  (testing "encrypt function test"
    (let [k (c/hex-to-bytes etalon-hash1)
          iv (c/hex-to-bytes "0102030405060708")
          e (c/gost-engine k iv true)
          cipher-text (c/encrypt e (.getBytes ^String etalon-string1))
          cs (c/bytes-to-hex cipher-text)]
      (is (= etalon-cipher-text cs)))))

(deftest decrypt-test
  (testing "decrypt function test"
    (let [k (c/hex-to-bytes etalon-hash1)
          iv (c/hex-to-bytes "0102030405060708")
          e (c/gost-engine k  iv false)
          cipher-text (c/hex-to-bytes etalon-cipher-text)
          plain-data (c/decrypt e cipher-text)
          plain-text (String. plain-data)]
      (is (= plain-text etalon-string1)))))