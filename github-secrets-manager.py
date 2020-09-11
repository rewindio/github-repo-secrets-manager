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

""" Test if the path is an org or a repo"""
def is_repo(path):
    if '/' in path:
        return True

    return False

"""Get the public key used to encrypt secrets for the org or a repo"""
def get_public_key(path, github_handle):
    global public_key_cache
    gh_status = 0
    key = {'key_id': '', 'key': ''}

    if path in public_key_cache:
        logging.debug("Public key cache hit for %s" % path)
        key = public_key_cache[path]
    else:
        logging.debug("Public key cache miss for %s" % path)

        if is_repo(path):
            owner, repo = path.split('/')

            if owner and repo:
                gh_status, data = github_handle.repos[owner][repo].actions.secrets['public-key'].get()
            else:
                logging.error("unable to determine owner and repo from %s" % path)
        else:
            # org key
            gh_status, data = github_handle.orgs[path].actions.secrets['public-key'].get()

        if gh_status == 200:
            logging.debug("Successfully read private key for %s" % path)
            public_key_cache[path] = data
            key = data
        else:
            logging.error("Error reading private key for %s : %d" % (path, gh_status))

    return key

"""Check if a secret already exists on a repo or for the org"""
def secret_exists(path, secret_name, github_handle):
    status = False
    gh_status = 0

    if is_repo(path):
        owner, repo = path.split('/')

        if owner and repo:
            gh_status, data = github_handle.repos[owner][repo].actions.secrets[secret_name].get()
        else:
            logging.error("unable to determine owner and repo from %s" % path)
    else:
        # This is an org secret
        gh_status, data = github_handle.orgs[path].actions.secrets[secret_name].get()

    if gh_status == 200:
        status = True
    
    return status

"""Add or update a secret in a github repo or org"""
def upsert_secret(path, secret_name, secret_val, github_handle):
    status = False
    gh_status = 0

    logger.info("Upserting path:%s sec:%s val:%s" % (path, secret_name, secret_val))

    public_key = get_public_key(path, github_handle)

    if public_key['key']:
        if public_key['key_id']:
            encrypted_secret = encrypt(public_key['key'], str(secret_val))

            request_body = {'encrypted_value': encrypted_secret, 'key_id': public_key['key_id']}
            request_headers = {'Content-Type': 'application/json'}

            if is_repo(path):
                owner, repo = path.split('/')

                if owner and repo:
                    gh_status, data = github_handle.repos[owner][repo].actions.secrets[secret_name].put(body=request_body, headers=request_headers)
                else:
                    logging.error("unable to determine owner and repo from %s" % path)
            else:
                # org secret
                request_body['visibility'] = 'private'  # this secret will only be visible to private repos in the org
                gh_status, data = github_handle.orgs[path].actions.secrets[secret_name].put(body=request_body, headers=request_headers)

            if gh_status == 204 or gh_status == 201:
                status = True
            else:
                logger.error("Error upserting secret %s : %d" % (path, gh_status))
        else:
            logging.error("No public key ID - unable to upsert secret")
    else:
        logging.error("No public key - unable to upsert secret")

    return status

"""Remove a secret from a github repo or org"""
def remove_secret(path, secret_name, github_handle):
    status = False

    if secret_exists(path, secret_name, github_handle):
        if is_repo(path):
            owner, repo = path.split('/')

            if owner and repo:
                gh_status, data = github_handle.repos[owner][repo].actions.secrets[secret_name].delete()
            else:
                logging.error("unable to determine owner and repo from %s" % path)
        else:
            # org secret
            gh_status, data = github_handle.orgs[path].actions.secrets[secret_name].delete()

        if gh_status == 204:
            status = True
        else:
            logger.error("Error removing secret %s : %d" % (path, gh_status))
    else:
        status = True  # Treat as if it was a removal if secret does not exist

    return status


if __name__ == "__main__":
    secrets = {}
    public_key_cache = {}
    repos_filter = []

    description = "Synchronize secrets with github repos\n"

    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("--secrets-file", help="Secrets file", dest='secrets_filename', required=True)
    parser.add_argument("--github-pat", help="Github access token", dest='github_pat', required=True)
    parser.add_argument("--verbose", help="Turn on DEBUG logging", action='store_true', required=False)
    parser.add_argument("--repos", help="Comma separated list of repos to be updated", dest='repos_filter', required=False)
    parser.add_argument("--dryrun", help="Do a dryrun - no changes will be performed", dest='dryrun',
                        action='store_true', default=False,
                        required=False)
    args = parser.parse_args()

    log_level = logging.INFO

    if args.verbose:
        print('Verbose logging selected')
        log_level = logging.DEBUG

    if args.repos_filter:
        repos_filter = args.repos_filter.split(',')

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

    # Loop over each secret in the config file
    # For each, determine if we are adding it to a repo or globally to an org
    for secret in secrets['secrets']:
        remove = False
        repos = []
        orgs = []

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

        if 'orgs' in secret:
            orgs.extend(secret['orgs'])

        if 'repos' in secret:
            repos.extend(secret['repos'])

        # Process any org values first
        if orgs:
            for org in orgs:
                if remove:
                    if dryrun:
                        logging.info("DRYRUN: Removing %s from org %s" % (secret_name, org))
                    else:
                        if remove_secret(org, secret_name, github_handle):
                            logging.info("Successfully removed secret %s from org %s" % (secret_name, org))
                        else:
                            logging.error("Unable to remove secret %s from org %s" % (secret_name, org))
                else:
                    if dryrun:
                        logging.info("DRYRUN: Adding %s to org %s" % (secret_name, org))
                    else:
                        if upsert_secret(org, secret_name, secret_val, github_handle):
                            logging.info("Successfully added/updated secret %s in org %s" % (secret_name, org))
                        else:
                            logging.error("Unable to add/update secret %s in org %s" % (secret_name, org))
                
        if repos:
            for repo in repos:
                repo = repo.strip()

                if ( len(repos_filter) > 0 and repo in repos_filter) or len(repos_filter) == 0:
                    if remove:
                        if dryrun:
                            logging.info("DRYRUN: Removing %s from repo %s" % (secret_name, repo))
                        else:
                            if remove_secret(repo, secret_name, github_handle):
                                logging.info("Successfully removed secret %s from repo %s" % (secret_name, repo))
                            else:
                                logging.error("Unable to remove secret %s from repo %s" % (secret_name, repo))
                    else:
                        if dryrun:
                            logging.info("DRYRUN: Adding %s to %s" % (secret_name, repo))
                        else:
                            if upsert_secret(repo, secret_name, secret_val, github_handle):
                                logging.info("Successfully added/updated secret %s in repo %s" % (secret_name, repo))
                            else:
                                logging.error("Unable to add/update secret %s in repo %s" % (secret_name, repo))

    logging.info("Complete")
