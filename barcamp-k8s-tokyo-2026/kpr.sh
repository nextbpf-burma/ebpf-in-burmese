helm repo add cilium https://helm.cilium.io/

echo "help install complete"

helm install cilium cilium/cilium --version 1.19.1 \
   --namespace kube-system \
   --set kubeProxyReplacement=true \
   --set k8sServiceHost=${API_SERVER_IP} \
   --set k8sServicePort=${API_SERVER_PORT}
