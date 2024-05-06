package conf

import "k8sRBACdetect/structure"

// Scan the account using at least the required permissions：Pods(list、`get`)、ClusterRoleBinding(list is used to collect SA names and Role names)、RoleBinding(Full space list)、sa(Full space get is used to view the mounting properties. Since they are mounted by default, it is generally possible without this permission.)、
// ClusterRole(get is used to view permissions verb)、Role(Full space get)、Nodes(list is used to find remaining normal nodes when Patch)
var AdminCert = ""
var AdminCertKey = ""
var ApiServer = ""
var TokenFile = ""
var Kubeconfig = ""
var ProxyAddress = ""
var SSH structure.SSHConfig
