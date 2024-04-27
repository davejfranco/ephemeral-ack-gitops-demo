#!/bin/bash 

secret() {
  CREDS_CONTENT=$(cat ~/.aws/credentials)
  cat <<EOF | kubectl apply -f -
---
apiVersion: v1
kind: Secret
metadata:
  name: aws-creds
type: Opaque
stringData:
  credentials-file: |
  $CREDS_CONTENT
EOF
}

install () {
  aws ecr-public get-login-password --region us-east-1 | helm registry login --username AWS --password-stdin public.ecr.aws
  
  kubectl create ns ack-system
  echo "Installing ACK credentials"
  secret
  
  echo "Installing s3 controller"
  helm upgrade --install s3 oci://public.ecr.aws/aws-controllers-k8s/s3-chart --version=1.0.11 -f s3-values.yaml

  echo "Installing iam controller"
  helm upgrade --install iam oci://public.ecr.aws/aws-controllers-k8s/iam-chart --version=1.3.7 -f iam-values.yaml

  echo "Installing ec2 controller"
  helm upgrade --install ec2 oci://public.ecr.aws/aws-controllers-k8s/ec2-chart --version=1.2.4 -f ec2-values.yaml

}

uninstall () {
  helm uninstall s3
  helm uninstall iam
  helm uninstall ec2
  kubectl delete ns ack-system
}

case $1 in
  install)
    install
    ;;
  uninstall)
    uninstall
    ;;
  *)
    echo "Usage: $0 {install|uninstall}"
    exit 1
    ;;
esac



