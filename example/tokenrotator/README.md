# Token Rotator

Tokens should be passed to clients running on Kubernetes via a secret.
They will need to be periodically rotated as they get close to expiry.
This example rotator does introspection on the token to discover its service account, then rotates the access token secret as necessary.

This provides a proof of concept that you may choose to use, but is not an official product.
Feel free to tweak any instructions to suit your particular environment.

## Building

From the root directory of the repository, build the rotator binary:

```shell
CGO_ENABLED=0 go build -o tokenrotator ./example/tokenrotator/
```

Next create a container image:

```shell
docker build -f example/tokenrotator/Dockerfile -t ghcr.io/unikorn-cloud/tokenrotator:v0.0.1 .
```

## Deploying

Again we provide a rudimentary example of how to actually deploy this in a safe and secure manner:

```shell
kubectl apply -f example/tokenrotator/deployment.yaml
```
