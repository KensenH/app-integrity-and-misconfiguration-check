#!/bin/bash

#script to generate tls certificate for webhook server

fn=tls

mkdir $fn

openssl genrsa -out $fn/ca.key 2048

openssl req -new -x509 -days 365 -key $fn/ca.key \
  -subj "/C=AU/CN=admission-controller-webhook"\
  -out $fn/ca.crt

openssl req -newkey rsa:2048 -nodes -keyout $fn/server.key \
  -subj "/C=AU/CN=admission-controller-webhook" \
  -out $fn/server.csr

openssl x509 -req \
  -extfile <(printf "subjectAltName=DNS:admission-controller-webhook.default.svc") \
  -days 365 \
  -in $fn/server.csr \
  -CA $fn/ca.crt -CAkey $fn/ca.key -CAcreateserial \
  -out $fn/server.crt

 echo
 echo ">> Generating kube secrets..."
 kubectl create secret tls simple-kubernetes-webhook-tls \
   --cert=$fn/server.crt \
   --key=$fn/server.key \
   --dry-run=client -o yaml \
   > charts/templates/secrets.yaml

# echo
# echo ">> MutatingWebhookConfiguration caBundle:"
cat $fn/ca.crt | base64 | fold

yes | rm -r ./$fn
