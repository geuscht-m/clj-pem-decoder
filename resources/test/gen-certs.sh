#!/bin/sh

openssl req -x509 -config /etc/ssl/openssl.cnf -new -nodes -keyout ca-root.key -sha256 -days 365 -out ca-root.crt -subj "/C=US/ST=NY/L=NYC/O=TEST/CN=pem-decoder.test"
openssl req -config /etc/ssl/openssl.cnf -new -nodes -keyout test-cert.key -out test-cert.csr -days 365 -subj "/C=US/ST=NY/L=NYC/O=TEST/OU=Users/CN=pem-decoder.test-user"
openssl x509 -req -days 365 -sha256 -in test-cert.csr -CA ca-root.crt -CAkey ca-root.key -CAcreateserial -extfile client_auth.cnf -out test-cert.crt
cat test-cert.key test-cert.crt > test-cert.pem
cat test-cert.key test-cert.crt ca-root.crt > test-cert-chain.pem
