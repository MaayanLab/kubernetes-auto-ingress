# kubernetes-auto-ingress

Auto-generate kubernetes ingresses based on a deployment annotation.

Assumes namespace kube-system exists, and deployments also have services created for them with the same name (as is the case for rancher deployments).

By default, it watches the default namespace for deployments with the (changable) `maayanlab.cloud/ingress` annotation key specifying the path to mount your app onto. It also expects a labeled port in your deployment spec named 'http' referring to the port to forward *to*.

```yaml
metadata:
  annotations:
    maayanlab.cloud/ingress: https://example.org/your_path # your path
spec:
  template:
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

### Install
```bash
kubectl create -f https://raw.githubusercontent.com/MaayanLab/kubernetes-auto-ingress/master/deployment.yaml
```

## Development

### Build
```bash
docker build -t maayanlab/kubernetes-auto-ingress:latest .
```

### Publish
```bash
docker push maayanlab/kubernetes-auto-ingress:latest
```
