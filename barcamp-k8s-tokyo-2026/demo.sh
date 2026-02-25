for i in {1..5}; do
    kubectl create deployment demo-$i --image=nginx --replicas=2
    kubectl expose deployment demo-$i --port=80
done
