# github-repo-secrets-manager

Manage github repo secrets using a common configuration file.  Supports repos, orgs and groups of secrets.

## Installation

```bash
git clone rewindio/github-repo-secrets-manager
pip3 install -r requirements.txt
```

## Prerequistes

- A Github Personal Access Token (PAT) that has repo and admin:org scopes

## Usage

```bash
usage: github-secrets-manager.py [-h] --secrets-file SECRETS_FILENAME
                                 --github-pat GITHUB_PAT [--verbose]
                                 [--repos REPOS_FILTER] [--dryrun]

Synchronize secrets with github repos

optional arguments:
  -h, --help            show this help message and exit
  --secrets-file SECRETS_FILENAME
                        Secrets file
  --github-pat GITHUB_PAT
                        Github access token
  --verbose             Turn on DEBUG logging
  --repos REPOS_FILTER  Comma separated list of repos to be updated
  --dryrun              Do a dryrun - no changes will be performed
```

```bash
./github-secrets-manager.py --secrets-file github_secrets.yaml --github-pat 123456789
```

### Notes

- The --repos option acts only as a filter when processing the secrets file.
- The repos must be defined in the secrets file to be updated

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
  -
    name: SECRET4
    value: 'an org level secret'

    orgs:
      - acme
```

**Note**
If the `value` field is missing or set to empty string, it will be removed from the repo
