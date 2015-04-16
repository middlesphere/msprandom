(ns msprandom.kbd
  (:gen-class)
  (:import (jline.console ConsoleReader)
           (clojure.lang Atom)))

(defn- run-counter
  "Run an infinite cycle and increment external ^Atom counter with very high speed in range 0..255.
  If external ^Atom go-flag? is false, then stop.
  Returns nil."
  [^Atom c
   ^Atom go-flag?]
  (while @go-flag?
    (swap! c inc)
    (if (>= @c 255)
      (reset! c 0))))

(defn kbdrand
  "Generates a true random bytes produced by human input from keyboard.
  This function must be run in console mode.
  Returns byte array of random data length of bytes-needed or nil."
  [^long bytes-needed]
  (when (> bytes-needed 0)
    (let [counter (atom 0)                                  ;internal incrementing counter
          scan-rdr (ConsoleReader.)                         ;get scan code reader
          go-flag? (atom true)]                             ;increment counter until this flag is false
      (future (run-counter counter go-flag?))               ;run increment function in a separate thread
      (println "please, press buttons in arbitrary way to generate random numbers...")
      (flush)
      (loop [acc (dec bytes-needed)
             v []]                                          ;loop until acc < bytes-needed-1
        (let [scan-code (mod (.readCharacter scan-rdr) 256) ;read scan code and take mod 256
              counter-value @counter                        ;read current counter value
              nano-value (mod (System/nanoTime) 256)        ;read current nano value and take mod 256
              rnd-value (bit-xor scan-code counter-value nano-value) ;xor values: scan-code ^ counter-value ^ nano-value to produce final random byte.
              rnd-byte (.byteValue rnd-value)               ;convert to byte format
              vv (conj v rnd-byte)]
          (print (format "\r=>%.2f%% done.   " (* 100.0 (/ (- bytes-needed acc) bytes-needed))))
          (flush)
          (if (> acc 0)
            (recur (dec acc) vv)
            (do
              (reset! go-flag? false)                       ;stop counter thread
              (.shutdown scan-rdr)                          ;shutdown console reader
              (println "")
              (byte-array vv))))))))                        ;return byte array with random data
