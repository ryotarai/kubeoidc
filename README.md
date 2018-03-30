# kubeoidc

kubeoidc works as OpenID Connect client for kubectl. This is tested to work with [coreos/dex](https://github.com/coreos/dex).

## Installation

Please download built binaries from https://github.com/ryotarai/kubeoidc/releases

Or you can build it yourself:

```
$ go get github.com/ryotarai/kubeoidc
```

## Usage

1. Run `kubeoidc -issuer=https://your-dex.example.com -client-id=oidc-client-id -client-secret=oidc-client-secret`
2. The login page provided by OIDC issuer will be shown in a web browser.
3. After logging in, kubeoidc shows you a configuration snippet for kubectl.
