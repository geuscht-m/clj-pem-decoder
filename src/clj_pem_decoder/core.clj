(ns clj-pem-decoder.core
  (:require [clojure.java.io :as io]
            [clojure.string :as str]))

(defn- extract-private-key
  [pem-string]
  ;;(println "pem-string is " pem-string)
  (let [potential-private-key (re-matches #"(-----BEGIN PRIVATE KEY-----(.+)-----END PRIVATE KEY-----).*" pem-string)]
    ;;(println "Potential private key is " potential-private-key)
    (if (< (count potential-private-key) 2)
      (let [potential-rsa-key (re-matches #"(-----BEGIN RSA PRIVATE KEY-----(.*)-----END RSA PRIVATE KEY-----).*" pem-string)]
        (println "Potential RSA private key is " potential-rsa-key)
        (if (> (count potential-rsa-key) 1)
          (nth potential-rsa-key 1)
          nil))
      (nth potential-private-key 2))))

(defn- extract-certificates
  [pem-string]
  (let [potential-certificates (re-matches #"(-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----)*(-----BEGIN CERTIFICATE-----(.+)-----END CERTIFICATE-----)+" pem-string)]
    (println "Certificate count " (count potential-certificates))
    (println "Potential certificates : " potential-certificates)
    (if (< (count potential-certificates) 3)
      (println "no cert found")
      (drop 2 potential-certificates))))

(defn decode-pem
  "Read a PEM file in standard format (private key first when present, followed
   by the certificate(s) and returns a map containing both the private key if
   present, and the certificate(s)"
  [pemfile]
  (with-open [input (io/input-stream pemfile)]
    (let [data         (str/replace (slurp input) #"\n" "")
          private-key  (extract-private-key data)
          certificates (extract-certificates data)]
      (println "data is " data)
      (println "Private key is " private-key)
      (println "Certificates are " certificates)
      { :private-key private-key :certificates certificates })))
          
