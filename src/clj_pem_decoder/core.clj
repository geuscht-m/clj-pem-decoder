(ns clj-pem-decoder.core
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import java.util.ArrayList
           java.security.cert.CertificateFactory
           java.io.ByteArrayInputStream
           java.util.Base64))

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

(defn decode-pem
  "Read a PEM file in standard format (private key first when present, followed
   by the certificate(s) and returns a map containing both the private key if
   present, and the certificate(s)"
  [pemfile]
  (let [pem-blocks   (load-n-parse-pemfile pemfile)
        as-block-seq (map determine-block-type pem-blocks)]
    (if (= (get (first as-block-seq) :type) :private-key)
      (doto (println "Found private key, creating both private key and certificate object(s)"))
      { :private-key nil :certificates (map create-cert as-block-seq)})))
          
