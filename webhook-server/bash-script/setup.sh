#!/bin/bash

#script to automate admission controller and webhook server deployment


# please, make sure change kube context to desired cluster


[ "$UID" -eq 0 ] || exec sudo "$0" "$@"

#download dependencies
# source ./dependencies.sh

#generate tls certificate
source ./gen-certs.sh

#build docker image and push
# DOCKER_BUILDKIT=1 docker build . -t kensenh/simple-kubernetes-webhook
# docker push kensenh/simple-kubernetes-webhook:latest

#deploy