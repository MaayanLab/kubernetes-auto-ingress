# kubernetes-auto-ingress

Auto-generate kubernetes ingresses based on a deployment annotation.

Assumes namespace kube-system exists, and deployments also have services created for them with the same name (as is the case for rancher deployments).

By default, it watches the default namespace for deployments with the (changable) `maayanlab.cloud/ingress` annotation key specifying the path to mount your app onto. It also expects a labeled port in your deployment spec named 'http' referring to the port to forward *to*.

```yaml
metadata:
spec:
  template:
    metadata:
      annotations:
        maayanlab.cloud/ingress: https://example.org/your_path # your path
    spec:
      containers:
      - image: your_image
        ports:
        - containerPort: 80 # your_http_port
          name: http
          protocol: TCP
```

This registers an annotation with the same key-value pair, and uses it to determine whether or not it should be managed by the utility. Other ingresses without the annotation will be ignored.


## Installation

### Pre-install RBAC setup
Setup service account for cluster
```bash
kubectl create serviceaccount --namespace kube-system tiller
kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
```

If you change the service account name, you'll need to modify the deployment. tiller is probably already there if you use helm.

### Install
```bash
kubectl create -f https://raw.githubusercontent.com/MaayanLab/kubernetes-auto-ingress/master/deployment.yaml
```

## Development

### Build
```bash
docker build -t maayanlab/auto-ingress:latest .
```

### Publish
```bash
docker push maayanlab/auto-ingress:latest
```
