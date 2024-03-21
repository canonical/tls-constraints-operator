# TLS Constraints
[![CharmHub Badge](https://charmhub.io/tls-constraints/badge.svg)](https://charmhub.io/tls-constraints)

This charm is used to filter certificate requests sent to a certificates provider.
This initial version only acts a proxy between the requirer and provider, allowing every
requests through.

## Usage

Deploy the charm and integrate it to a certificate requirer, and to a certificate provider:

```bash
juju deploy tls-constraints --channel beta
juju integrate tls-constraints:certificates-downstream <TLS Certificates Requirer>
juju integrate tls-constraints:certificates-upstream <TLS Certificates Provider>
```

## Integrations

This charm provides and requests certificates using the `tls-certificates` integration.
