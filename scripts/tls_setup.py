#!/usr/bin/env python3

import os
from pathlib import Path
import sys
import argparse
import subprocess
import tempfile
import socket
import base64
import secrets

from hostlist import expand_hostlist

# Constants
CERT_PATH_SUFFIX = "_cert.pem"
KEY_PATH_SUFFIX = "_cert_key.pem"
NODE_TOKEN_PATH_SUFFIX = "_token.txt"
CERT_PERMS = 0o444
SIGNED_CERT_PERMS = 0o400
KEY_PERMS = 0o400
SCRIPT_PERMS = 0o755

CA_ID = "ca"
SLURMCTLD_ID = "ctld"
SLURMDBD_ID = "dbd"
SLURMRESTD_ID = "restd"
SLURMD_ID = "slurmd"
SACKD_ID = "sackd"


class ArgNamespace:
    slurm_etc: Path
    slurm_user: str
    slurmrestd_user: str
    use_certmgr: bool
    nodes: str
    targets: set[str]
    gen_conf_snippets: bool

    ca_cert_path: Path
    ca_key_path: Path
    dbd_cert_path: Path
    dbd_key_path: Path
    slurmd_cert_path: Path
    slurmd_key_path: Path

    node_token_list_path: Path

    get_node_token_script_path: Path
    gen_csr_script_path: Path
    validate_node_script_path: Path
    sign_csr_script_path: Path
    get_node_key_script_path: Path

    def __init__(self, args: argparse.Namespace):
        self.slurm_etc: Path = Path(args.slurm_etc)
        self.slurm_user: str = args.slurm_user
        self.slurmrestd_user: str = args.slurmrestd_user
        self.use_certmgr: bool = args.use_certmgr
        self.nodes: str = args.nodes
        self.targets: set[str] = set(args.gen_target)
        self.gen_conf_snippets: bool = args.gen_conf_snippets

        self.ca_cert_path = self.slurm_etc / f"{CA_ID}{CERT_PATH_SUFFIX}"
        self.ca_key_path = self.slurm_etc / f"{CA_ID}{KEY_PATH_SUFFIX}"

        self.dbd_cert_path = self.slurm_etc / f"{SLURMDBD_ID}{CERT_PATH_SUFFIX}"
        self.dbd_key_path = self.slurm_etc / f"{SLURMDBD_ID}{KEY_PATH_SUFFIX}"
        self.slurmd_cert_path = self.slurm_etc / f"%n_{SLURMD_ID}{CERT_PATH_SUFFIX}"
        self.slurmd_key_path = self.slurm_etc / f"%n_{SLURMD_ID}{KEY_PATH_SUFFIX}"

        self.node_token_list_path = self.slurm_etc / "node_token_list.txt"

        self.get_node_token_script_path = self.slurm_etc / "certmgr_get_node_token.sh"
        self.gen_csr_script_path = self.slurm_etc / "certmgr_gen_csr.sh"
        self.validate_node_script_path = self.slurm_etc / "certmgr_validate_node.sh"
        self.sign_csr_script_path = self.slurm_etc / "certmgr_sign_csr.sh"
        self.get_node_key_script_path = self.slurm_etc / "certmgr_get_node_key.sh"

    def validate_input(args):
        if not os.path.isdir(args.slurm_etc):
            print(
                f"Error: Directory '{args.slurm_etc}' specified by --slurm-etc does not exist."
            )

    def __repr__(self):
        return "ArgNamespace:\n{}".format(
            "\n".join(f"{k}: {v}" for k, v in self.__dict__.items())
        )


def run(args):
    print(" ".join(str(arg) for arg in args))
    return subprocess.run(args, check=True)


def setup_perms(permissions, path, user):
    try:
        os.chmod(path, permissions)
    except OSError:
        print(f'{sys.argv[0]}: Failed to set perms {oct(permissions)} key at "{path}"')
        sys.exit(1)

    try:
        # Get user ID
        import pwd

        uid = pwd.getpwnam(user).pw_uid
        gid = pwd.getpwnam(user).pw_gid
        os.chown(path, uid, gid)
    except (OSError, KeyError):
        print(f'{sys.argv[0]}: Failed to chown for user "{user}" key at "{path}"')
        sys.exit(1)


def generate_private_key(key_file_path, user):
    try:
        run(
            [
                "openssl",
                "ecparam",
                "-out",
                key_file_path,
                "-name",
                "prime256v1",
                "-genkey",
            ],
        )
    except subprocess.CalledProcessError:
        print(f'{sys.argv[0]}: Failed to create private key at "{key_file_path}"')
        sys.exit(1)

    # set permissions on key
    setup_perms(KEY_PERMS, key_file_path, user)


def generate_ca_cert(args: ArgNamespace):
    generate_private_key(args.ca_key_path, args.slurm_user)

    # generate self-signed certificate
    try:
        run(
            [
                "openssl",
                "req",
                "-x509",
                "-key",
                args.ca_key_path,
                "-out",
                args.ca_cert_path,
                "-subj",
                f"/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN={CA_ID}",
            ],
        )
    except subprocess.CalledProcessError:
        print(
            f'{sys.argv[0]}: Failed to CA cert at "{args.ca_cert_path}" with key at "{args.ca_key_path}"'
        )
        sys.exit(1)

    # set permissions on cert
    setup_perms(CERT_PERMS, args.ca_cert_path, args.slurm_user)


def generate_signed_cert(args: ArgNamespace, name: str, user: str):
    cert_path = f"{args.slurm_etc}/{name}{CERT_PATH_SUFFIX}"
    key_path = f"{args.slurm_etc}/{name}{KEY_PATH_SUFFIX}"

    csr_file = tempfile.NamedTemporaryFile()
    csr_path = Path(csr_file.name)

    try:
        generate_private_key(key_path, user)

        # generate csr
        try:
            run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-key",
                    key_path,
                    "-out",
                    csr_path,
                    "-subj",
                    f"/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN={name}",
                ],
            )
        except subprocess.CalledProcessError:
            print(f'{sys.argv[0]}: Failed to create CSR with key at "{key_path}"')
            sys.exit(1)

        # generate signed certificate using CSR and the CA certificate
        try:
            print(f"{csr_path.exists()=}")
            print(f"{csr_path.read_text()}")
            run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    csr_path,
                    "-CA",
                    args.ca_cert_path,
                    "-CAkey",
                    args.ca_key_path,
                    "-out",
                    cert_path,
                    "-sha384",
                    "-CAcreateserial",
                ],
            )
        except subprocess.CalledProcessError:
            print(
                f'{sys.argv[0]}: Failed to signed cert at "{cert_path}" with CSR at "{csr_path}"'
            )
            sys.exit(1)

        # set permissions on cert
        setup_perms(SIGNED_CERT_PERMS, cert_path, user)

    finally:
        csr_file.close()


def generate_token(args: ArgNamespace, node_name: str):
    node_token_path = f"{args.slurm_etc}/{node_name}{NODE_TOKEN_PATH_SUFFIX}"

    # Generate 32 bytes of random data and base64 encode it
    random_bytes = secrets.token_bytes(24)  # 24 bytes -> 32 chars when base64 encoded
    token = base64.b64encode(random_bytes).decode("ascii")

    with open(node_token_path, "w") as f:
        f.write(token)

    setup_perms(KEY_PERMS, node_token_path, args.slurm_user)

    with open(args.node_token_list_path, "a") as f:
        f.write(f"{node_name}: {token}\n")


def generate_node_tokens(args):
    if os.path.exists(args.node_token_list_path):
        os.remove(args.node_token_list_path)

    for node_name in expand_hostlist(args.nodes):
        generate_token(args, node_name)

    # generate token for sackd
    hostname = socket.gethostname().split(".")[0]
    generate_token(args, hostname)

    setup_perms(KEY_PERMS, args.node_token_list_path, args.slurm_user)


def generate_node_signed_certs(args):
    for node_name in expand_hostlist(args.nodes):
        generate_signed_cert(args, node_name, args.slurm_user)


def add_get_node_token_script(args: ArgNamespace):
    script_content = f"""#!/bin/bash

# Slurm node name is passed in as arg $1
TOKEN_PATH={args.slurm_etc}/$1{NODE_TOKEN_PATH_SUFFIX}
TOKEN_PERMISSIONS=400

# Check if token file exists
if [ ! -f $TOKEN_PATH ]
then
    echo "$BASH_SOURCE: Failed to resolve token path '$TOKEN_PATH'"
    exit 1
fi

# Check node private key permissions
if [ `stat -c "%a" $TOKEN_PATH` -ne $TOKEN_PERMISSIONS ]
then
    echo "$BASH_SOURCE: Bad permissions for node token at '$TOKEN_PATH'. Permissions should be $TOKEN_PERMISSIONS"
    exit 1
fi

# Print token to stdout
cat $TOKEN_PATH

# Exit with exit code 0 to indicate success
exit 0
"""
    args.get_node_token_script_path.write_text(script_content)
    setup_perms(SCRIPT_PERMS, args.get_node_token_script_path, args.slurm_user)


def add_validate_node_script(args: ArgNamespace):
    script_content = f"""#!/bin/bash

NODE_NAME=$1
NODE_TOKEN=$2
NODE_TOKEN_LIST_FILE={args.node_token_list_path}

# Check if node token list file exists
if [ ! -f $NODE_TOKEN_LIST_FILE ]
then
    echo "$BASH_SOURCE: Failed to resolve node token list path '$NODE_TOKEN_LIST_FILE'"
    exit 1
fi

# Check if unique node token is in token list file
grep "${{NODE_NAME}}: ${{NODE_TOKEN}}" $NODE_TOKEN_LIST_FILE

# Check exit code from grep to see if token was found
if [ $? -ne 0 ]
then
    echo "$BASH_SOURCE: Failed to validate token '$NODE_TOKEN'"
    exit 1
fi

# Exit with exit code 0 to indicate success (node token is valid)
exit 0
"""
    args.validate_node_script_path.write_text(script_content)
    setup_perms(SCRIPT_PERMS, args.validate_node_script_path, args.slurm_user)


def add_gen_csr_script(args: ArgNamespace):
    script_content = f"""#!/bin/bash

# Slurm node name is passed in as arg $1
NODE_PRIVATE_KEY={args.slurm_etc}/$1{KEY_PATH_SUFFIX}

openssl ecparam -out $NODE_PRIVATE_KEY -name prime256v1 -genkey

# Check exit code from openssl
if [ $? -ne 0 ]
then
    echo "$BASH_SOURCE: Failed to generate private key"
    exit 1
fi

chmod 0400 $NODE_PRIVATE_KEY

# Generate CSR using node private key and print CSR to stdout
openssl req -new -key $NODE_PRIVATE_KEY \\
    -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=$1"

# Check exit code from openssl
if [ $? -ne 0 ]
then
    echo "$BASH_SOURCE: Failed to generate CSR"
    exit 1
fi

# Exit with exit code 0 to indicate success
exit 0
"""

    with open(args.gen_csr_script_path, "w") as f:
        f.write(script_content)

    setup_perms(SCRIPT_PERMS, args.gen_csr_script_path, args.slurm_user)


def add_sign_csr_script(args: ArgNamespace):
    script_content = f"""#!/bin/bash

# Certificate signing request is passed in as arg $1
CSR=$1
CA_CERT={args.ca_cert_path}
CA_KEY={args.ca_key_path}
KEY_PERMISSIONS=400

# Check if CA certificate file exists
if [ ! -f $CA_CERT ]
then
    echo "$BASH_SOURCE: Failed to resolve CA certificate path '$CA_CERT'"
    exit 1
fi

# Check if CA private key file exists
if [ ! -f $CA_KEY ]
then
    echo "$BASH_SOURCE: Failed to resolve CA private key path '$CA_KEY'"
    exit 1
fi

# Check CA private key permissions
if [ `stat -c "%a" $CA_KEY` -ne $KEY_PERMISSIONS ]
then
    echo "$BASH_SOURCE: Bad permissions for CA private key at '$CA_KEY'. Permissions should be $KEY_PERMISSIONS"
    exit 1
fi

# Sign CSR using CA certificate and CA private key and print signed cert to stdout
openssl x509 -req -CA $CA_CERT -CAkey $CA_KEY -not_after $(date -u -d '+1 day +10 minutes' "+%Y%m%d%H%M%S")Z 2>/dev/null <<< $CSR

# Check exit code from openssl
if [ $? -ne 0 ]
then
    echo "$BASH_SOURCE: Failed to generate signed certificate"
    exit 1
fi

# Exit with exit code 0 to indicate success
exit 0
"""
    args.sign_csr_script_path.write_text(script_content)
    setup_perms(SCRIPT_PERMS, args.sign_csr_script_path, args.slurm_user)


def add_get_node_key_script(args: ArgNamespace):
    script_content = f"""#!/bin/bash

# Slurm node name is passed in as arg $1
NODE_PRIVATE_KEY={args.slurm_etc}/$1{KEY_PATH_SUFFIX}

# Check if node private key file exists
if [ ! -f $NODE_PRIVATE_KEY ]
then
    echo "$BASH_SOURCE: Failed to resolve node private key path '$NODE_PRIVATE_KEY'"
    exit 1
fi

cat $NODE_PRIVATE_KEY

# Exit with exit code 0 to indicate success
exit 0
"""
    args.get_node_key_script_path.write_text(script_content)
    setup_perms(SCRIPT_PERMS, args.get_node_key_script_path, args.slurm_user)


def print_conf(args: ArgNamespace):
    if args.use_certmgr:
        slurm_conf = f"""
TLSType=tls/s2n
TLSParameters=\\
ctld_cert_file={args.slurm_etc}/{SLURMCTLD_ID}{CERT_PATH_SUFFIX},\\
ctld_cert_key_file={args.slurm_etc}/{SLURMCTLD_ID}{KEY_PATH_SUFFIX},\\
restd_cert_file={args.slurm_etc}/{SLURMRESTD_ID}{CERT_PATH_SUFFIX},\\
restd_cert_key_file={args.slurm_etc}/{SLURMRESTD_ID}{KEY_PATH_SUFFIX},\\
ca_cert_file={args.slurm_etc}/{CA_ID}{CERT_PATH_SUFFIX}

CertmgrType=certmgr/script
CertmgrParameters=\\
get_node_token_script={args.get_node_token_script_path},\\
generate_csr_script={args.gen_csr_script_path},\\
validate_node_script={args.validate_node_script_path},\\
sign_csr_script={args.sign_csr_script_path},\\
get_node_cert_key_script={args.get_node_key_script_path}
""".strip()
    else:
        slurm_conf = f"""
TLSType=tls/s2n
TLSParameters=\\
ctld_cert_file={args.slurm_etc}/{SLURMCTLD_ID}{CERT_PATH_SUFFIX},\\
ctld_cert_key_file={args.slurm_etc}/{SLURMCTLD_ID}{KEY_PATH_SUFFIX},\\
restd_cert_file={args.slurm_etc}/{SLURMRESTD_ID}{CERT_PATH_SUFFIX},\\
restd_cert_key_file={args.slurm_etc}/{SLURMRESTD_ID}{KEY_PATH_SUFFIX},\\
slurmd_cert_file={args.slurm_etc}/%n_{SLURMD_ID}{CERT_PATH_SUFFIX},\\
slurmd_cert_key_file={args.slurm_etc}/%n_{SLURMD_ID}{KEY_PATH_SUFFIX},\\
sackd_cert_file={args.slurm_etc}/{SACKD_ID}{CERT_PATH_SUFFIX},\\
sackd_cert_key_file={args.slurm_etc}/{SACKD_ID}{KEY_PATH_SUFFIX},\\
ca_cert_file={args.slurm_etc}/{CA_ID}{CERT_PATH_SUFFIX}
""".strip()

    slurmdbd_conf = f"""
TLSType=tls/s2n
TLSParameters=\\
dbd_cert_file={args.slurm_etc}/{SLURMDBD_ID}{CERT_PATH_SUFFIX},\\
dbd_cert_key_file={args.slurm_etc}/{SLURMDBD_ID}{KEY_PATH_SUFFIX},\\
ca_cert_file={args.ca_cert_path}
""".strip()

    print(
        f"""
Paste this into slurm.conf:
###############################################################################
{slurm_conf}
###############################################################################

Paste this into slurmdbd.conf:
###############################################################################
{slurmdbd_conf}
###############################################################################
"""
    )

    if args.gen_conf_snippets:
        slurm_conf_snip = Path(args.slurm_etc) / "tls_slurm_snippet.conf"
        slurm_conf_snip.write_text(slurm_conf)
        print(f"generated {slurm_conf_snip}")

        slurmdbd_conf_snip = Path(args.slurm_etc) / "tls_slurmdbd_snippet.conf"
        slurmdbd_conf_snip.write_text(slurmdbd_conf)
        print(f"generated {slurmdbd_conf_snip}")


def parse_arguments(argv) -> ArgNamespace:
    parser = argparse.ArgumentParser(
        description="Setup certificates, tokens, and scripts for TLS with certmgr/script"
    )
    parser.add_argument(
        "--slurm-etc", required=True, help="Absolute path to certmgr config directory"
    )
    parser.add_argument("--slurm-user", required=True, help="Slurm user")
    parser.add_argument(
        "--slurmrestd-user", required=True, help="User that runs slurmrestd"
    )
    parser.add_argument(
        "--gen-target",
        "-t",
        action="extend",
        nargs="+",
        choices=["slurm", "slurmctld", "slurmd", "slurmdbd", "slurmrestd", "sackd"],
        help="",
    )
    parser.add_argument(
        "--use-certmgr",
        action="store_true",
        help="Enable certmgr certificate generation",
    )
    parser.add_argument(
        "--nodes",
        action="store",
        help="nodes to generate tokens for",
    )
    parser.add_argument(
        "--gen-conf-snippets",
        action="store_true",
        help="generate config snippets as files",
    )

    args = ArgNamespace(parser.parse_args(argv))
    return args


def main(argv=sys.argv[1:]):
    args = parse_arguments(argv)
    args.validate_input()

    # Generate Slurm CA
    if "slurm" in args.targets:
        generate_ca_cert(args)

    # Generate daemon certificates
    if "slurmctld" in args.targets:
        generate_signed_cert(args, SLURMCTLD_ID, args.slurm_user)
    if "slurmdbd" in args.targets:
        generate_signed_cert(args, SLURMDBD_ID, args.slurm_user)
    if "slurmrestd" in args.targets:
        generate_signed_cert(args, SLURMRESTD_ID, args.slurmrestd_user)
    if "sackd" in args.targets:
        generate_signed_cert(args, SACKD_ID, args.slurm_user)

    if "slurmd" in args.targets:
        if args.use_certmgr:
            # Generate unique node tokens and token list file for slurmd validation
            generate_node_tokens(args)

            # Add all scripts for certmgr/script plugin
            add_get_node_token_script(args)
            add_validate_node_script(args)
            add_gen_csr_script(args)
            add_sign_csr_script(args)
            add_get_node_key_script(args)
        else:
            generate_node_signed_certs(args)

    print_conf(args)


if __name__ == "__main__":
    main()
