(ns clj-pem-decoder.core-test
  (:require [clojure.test :refer :all]
            [clj-pem-decoder.core :refer :all]))

(deftest load-basic-pem-test
  (testing "Check basic parsing"
    (println (clj-pem-decoder.core/decode-pem "resources/test/test-cert.pem"))))

(deftest load-pem-chain
  (testing "Check that we can load a basic test chain"
    (println (clj-pem-decoder.core/decode-pem "resources/test/test-cert-chain.pem"))))

(deftest load-root-cert
  (testing "Check that we can load a single certificate"
    (println (clj-pem-decoder.core/decode-pem "resources/test/ca-root.crt"))))
