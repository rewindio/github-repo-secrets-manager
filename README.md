# github-repo-secrets-manager

Manage github repo secrets using a common configuration file

## Installation

```bash
git clone rewindio/github-repo-secrets-manager
pip3 install -r requirements.txt
```

## Usage

```bash
usage: github-secrets-manager.py [-h] --secrets-file SECRETS_FILENAME
                                 --github-pat GITHUB_PAT [--verbose]
                                 [--dryrun]

Synchronize secrets with github repos

optional arguments:
  -h, --help            show this help message and exit
  --secrets-file SECRETS_FILENAME
                        Secrets file
  --github-pat GITHUB_PAT
                        Github access token
  --verbose             Turn on DEBUG logging
  --dryrun              Do a dryrun - no changes will be performed
```

```bash
./github-secrets-manager.py --secrets-file github_secrets.yaml --github-pat 123456789
```

## Configuration File

```yaml
groups:
  pandas:
    - someuser/my-repo
    - anotheruser/my-other-repo
  koalas:
    - someoneelse/some-other-repo

secrets:
  -
    name: SECRET1
    value: 'value1'

    repos:
      - myorg/repo-one
      - myorg/repo2
  -
    name: SECRET2
    value: 'value2'

    groups:
      - pandas
  -
    name: SECRET3
    value: ''

    repos:
      - myorg/repo-one
    groups:
      - koalas
```

**Note**
If the `value` field is missing or set to empty string, it will be removed from the repo
