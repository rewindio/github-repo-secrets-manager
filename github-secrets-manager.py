#!/usr/bin/env python3

import logging
import logging.handlers
import pkg_resources
import argparse
import yaml
from agithub.GitHub import GitHub
from pprint import pformat
from base64 import b64encode
from nacl import encoding, public

# version = pkg_resources.get_distribution('github-secrets-manager').version

# Small cache of repo pkeys to save some API calls
public_key_cache = {}


def read_secrets_file(filename):
    """Read the YAML configuration file"""
    logging.debug("read_secrets_file")
    secrets = {}
    secrets = yaml.safe_load(open(filename))
    return secrets


# https://developer.github.com/v3/actions/secrets/#create-or-update-a-secret-for-a-repository
def encrypt(public_key: str, secret_value: str) -> str:
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")


def get_repo_public_key(repo_path, github_handle):
    global public_key_cache
    key = {'key_id': '', 'key': ''}

    if repo_path in public_key_cache:
        logging.debug("Public key cache hit for repo %s" % repo_path)
        key = public_key_cache[repo_path]
    else:
        logging.debug("Public key cache miss for repo %s" % repo_path)
        owner, repo = repo_path.split('/')
        gh_status, data = github_handle.repos[owner][repo].actions.secrets['public-key'].get()

        if gh_status == 200:
            logging.debug("Successfully read private key for repo %s" % repo_path)
            public_key_cache[repo_path] = data
            key = data
        else:
            logging.error("Error reading private key for repo %s : %d" % (repo_path, gh_status))

    return key


def secret_exists(repo_path, secret_name, github_handle):
    status = False
    owner, repo = repo_path.split('/')

    if owner and repo:
        gh_status, data = github_handle.repos[owner][repo].actions.secrets[secret_name].get()

        if gh_status == 200:
            status = True
    else:
        logging.error("unable to determine owner and repo from %s" % repo_path)

    return status


def upsert_secret(repo_path, secret_name, secret_val, github_handle):
    """Add or update a secret in a github repo."""
    status = False
    owner, repo = repo_path.split('/')

    if owner and repo:
        public_key = get_repo_public_key(repo_path, github_handle)

        if public_key['key']:
            encrypted_secret = encrypt(public_key['key'], secret_val)

            if public_key['key_id']:
                request_body = {'encrypted_value': encrypted_secret, 'key_id': public_key['key_id']}
                request_headers = {'Content-Type': 'application/json'}

                gh_status, data = github_handle.repos[owner][repo].actions.secrets[secret_name].put(body=request_body, headers=request_headers)

                if gh_status == 204 or status == 201:
                    status = True
                else:
                    logger.error("Error upserting secret %s : %d" % (repo_path, gh_status))
            else:
                logging.error("No public key ID - unable to upsert secret")
        else:
            logging.error("No public key - unable to upsert secret")
    else:
        logging.error("unable to determine owner and repo from %s" % repo_path)

    return status


def remove_secret(repo_path, secret_name, github_handle):
    """Remove a secret from a github repo."""
    status = False
    owner, repo = repo_path.split('/')

    if owner and repo:
        if secret_exists(repo_path, secret_name, github_handle):
            gh_status, data = github_handle.repos[owner][repo].actions.secrets[secret_name].delete()

            if gh_status == 204:
                status = True
            else:
                logger.error("Error removing secret %s : %d" % (repo_path, gh_status))
        else:
            status = True  # Treat as if it was a removal if secret does not exist
    else:
        logging.error("unable to determine owner and repo from %s" % repo_path)

    return status


if __name__ == "__main__":

    secrets = {}
    public_key_cache = {}

    description = "Synchronize secrets with github repos\n"

    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("--secrets-file", help="Secrets file", dest='secrets_filename', required=True)
    parser.add_argument("--github-pat", help="Github access token", dest='github_pat', required=True)
    parser.add_argument("--verbose", help="Turn on DEBUG logging", action='store_true', required=False)
    parser.add_argument("--dryrun", help="Do a dryrun - no changes will be performed", dest='dryrun',
                        action='store_true', default=False,
                        required=False)
    args = parser.parse_args()

    log_level = logging.INFO

    if args.verbose:
        print('Verbose logging selected')
        log_level = logging.DEBUG

    # if set, make no changes and log only what would happen
    dryrun = args.dryrun

    # Setup some logging
    logger = logging.getLogger()
    logger.setLevel(log_level)
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    console_formatter = logging.Formatter('%(levelname)8s: %(message)s')
    ch.setFormatter(console_formatter)
    logger.addHandler(ch)

    # Read the yaml file
    secrets = read_secrets_file(args.secrets_filename)
    logging.debug(pformat(secrets))

    # Initialize connection to Github API
    github_handle = GitHub(token=args.github_pat)

    # Loop over every entry in the config
    # For each entry, get the public key for the repo and encrpt the secret
    # Write the secret

    for secret in secrets['secrets']:
        remove = False
        repos = []

        if secret and 'name' in secret:
            secret_name = secret['name'].strip()
            logging.info("Secret found: %s" % secret_name)

        if 'value' in secret and secret['value']:
            secret_val = secret['value']
        else:
            # We assume if there is no value, we are removing the secret
            logging.info("No value defined for %s - removing parameter from all repos" % secret_name)
            remove = True

        if 'groups' in secret:
            for group in secret['groups']:
                if group in secrets['groups']:
                    repos.extend(secrets['groups'][group])
                else:
                    logging.info("No group defined for %s" % group)

        if 'repos' in secret:
            repos.extend(secret['repos'])

        if repos:
            for repo in repos:
                repo = repo.strip()

                if remove:
                    if dryrun:
                        logging.info("DRYRUN: Removing %s from %s" % (secret_name, repo))
                    else:
                        if remove_secret(repo, secret_name, github_handle):
                            logging.info("Successfully removed secret %s from %s" % (secret_name, repo))
                        else:
                            logging.error("Unable to remove secret %s from %s" % (secret_name, repo))
                else:
                    if dryrun:
                        logging.info("DRYRUN: Adding %s to %s" % (secret_name, repo))
                    else:
                        if upsert_secret(repo, secret_name, secret_val, github_handle):
                            logging.info("Successfully added/updated secret %s in repo %s" % (secret_name, repo))
                        else:
                            logging.error("Unable to add/update secret %s in repo %s" % (secret_name, repo))
        else:
            logging.error("No name for secret - unable to manage")

    logging.info("Complete")
