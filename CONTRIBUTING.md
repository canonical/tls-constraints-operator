# Contributing

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate


## Building the charm

With charmcraft and LXD installed and initialized, run:

```bash
charmcraft pack
```

## Testing

### Unit tests

```bash
tox -e unit
```

### Static analysis

```bash
tox -e static
```

### Linting

```bash
tox -e lint
```

### Integration tests

To run the integration tests, you will need to have Juju and MicroK8s installed
and bootstrapped.

You will also require to have built the charm locally.

```bash
tox -e integration -- --charm_path=./tls-constraints_ubuntu-22.04-amd64.charm
```
