# TLS and mTLS test certificates

Generate test material in a directory outside the repository. The commands below use a private CA, one server certificate, and one certificate per agent. Keep `ca.key`, `node*.key`, and PKCS12 files outside source control.

```sh
umask 077
mkdir sentinelx-certs && cd sentinelx-certs
PASSWORD='change-this-outside-the-repository'

openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -subj '/CN=SentinelX Test CA' -keyout ca.key -out ca.crt

openssl req -newkey rsa:2048 -nodes -subj '/CN=node3' -keyout node3.key -out node3.csr
printf 'subjectAltName=DNS:node3,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > node3.ext
openssl x509 -req -in node3.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
  -out node3.crt -extfile node3.ext

for agent in nodo1 nodo2; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$agent" -keyout "$agent.key" -out "$agent.csr"
  printf 'extendedKeyUsage=clientAuth\n' > "$agent.ext"
  openssl x509 -req -in "$agent.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
    -out "$agent.crt" -extfile "$agent.ext"
done

openssl pkcs12 -export -name node3 -inkey node3.key -in node3.crt -certfile ca.crt -out node3.p12 -passout pass:"$PASSWORD"
for agent in nodo1 nodo2; do
  openssl pkcs12 -export -name "$agent" -inkey "$agent.key" -in "$agent.crt" -certfile ca.crt -out "$agent.p12" -passout pass:"$PASSWORD"
done
keytool -importcert -noprompt -alias sentinelx-ca -file ca.crt -keystore node3-truststore.p12 -storetype PKCS12 -storepass "$PASSWORD"
for agent in nodo1 nodo2; do
  keytool -importcert -noprompt -alias sentinelx-ca -file ca.crt -keystore "$agent-truststore.p12" -storetype PKCS12 -storepass "$PASSWORD"
done
```

Copy only the required public/configuration material and PKCS12 files to the deployment host using an approved secret-management process. Set `SENTINELX_TLS_KEYSTORE_PASSWORD` and `SENTINELX_TLS_TRUSTSTORE_PASSWORD` in the service environment. Enable `tls.enabled=true` on all three nodes and `tls.requireClientAuth=true` on Node 3. A client without a certificate signed by the CA is rejected during the TLS handshake.