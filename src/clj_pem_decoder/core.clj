(ns clj-pem-decoder.core
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import java.util.ArrayList
           [java.security.cert CertificateFactory Certificate X509Certificate] 
           java.io.ByteArrayInputStream
           java.util.Base64
           java.security.KeyFactory
           java.security.spec.PKCS8EncodedKeySpec))

(defn- load-n-parse-pemfile
  [pem-file-name]
  (with-open [input (io/reader pem-file-name)]
    (let [in-block (volatile! false)
          block    (new StringBuilder)
          blocks   (new ArrayList)]
      (doseq [line (line-seq input)]
        (.append block line)
        ;;(println block)
        (if (str/starts-with? line "-----")
          (if @in-block
            (let [new-block (.toString block)]
              ;;(println (type new-block) ", " new-block)
              (.add blocks new-block)
              (vreset! in-block false)              
              (.setLength block 0))
            (vreset! in-block true))))
      (into [] blocks))))

(defn- determine-block-type
  [pem-block]
  (let [block-type (re-matches #"-----BEGIN\s(.+)-----(.+)-----END\s(.+)-----" pem-block)]
    (assert (= (nth block-type 1) (nth block-type 3)))
    (cond
      (= (nth block-type 1) "PRIVATE KEY") { :type :private-key :data (nth block-type 2)}
      (= (nth block-type 1) "CERTIFICATE") { :type :certificate :data (nth block-type 2)})))

(defn- create-cert
  [cert-data]
  (assert (= (get cert-data :type) :certificate))
  (let [bin-cert (.decode (Base64/getDecoder) (get cert-data :data))
        bin-in   (ByteArrayInputStream. bin-cert)
        cf (CertificateFactory/getInstance "X.509")]
    (.generateCertificate cf bin-in)))

(defn- create-cert-array
  [block-seq]
  (into-array (if (= (get (first block-seq) :type) :private-key)
                (map create-cert (rest block-seq))
                (map create-cert block-seq))))

(defn- create-private-key
  [block-seq cert-arr]
  (if (= (get (first block-seq) :type) :private-key)
    (let [bin-key (.decode (Base64/getDecoder) (get (first block-seq) :data))
          key     (PKCS8EncodedKeySpec. bin-key)]
      (.generatePrivate (KeyFactory/getInstance "RSA") key))
    nil))

(defn decode-pem
  "Read a PEM file in standard format (private key first when present, followed
   by the certificate(s) and returns a map containing both the private key if
   present, and the certificate(s)"
  [pemfile]
  (let [pem-blocks   (load-n-parse-pemfile pemfile)
        as-block-seq (map determine-block-type pem-blocks)
        cert-arr     (create-cert-array as-block-seq)]
    { :private-key (create-private-key as-block-seq cert-arr)     
     :certificates cert-arr}))
          
