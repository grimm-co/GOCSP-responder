#! /bin/sh
# ==================================================================
#  _                                         
# | |                                        
# | |     __ _ _ __ ___   __ _ ___ ___ _   _ 
# | |    / _` | '_ ` _ \ / _` / __/ __| | | |
# | |___| (_| | | | | | | (_| \__ \__ \ |_| |
# |______\__,_|_| |_| |_|\__,_|___/___/\__,_|
#                                            
#                                            
# ==================================================================

minikube kubectl -- create secret generic ocsp-ca --from-file=./ca/enroller.crt
minikube kubectl -- create secret generic ocsp-certs --from-file=./certs/consul.crt --from-file=./certs/responder-pkcs8.key --from-file=./certs/responder.crt --from-file=./certs/responder.key

minikube kubectl -- apply -f k8s/ocsp-deployment.yml
minikube kubectl -- apply -f k8s/ocsp-service.yml