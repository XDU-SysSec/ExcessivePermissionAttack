package conf

import "k8sRBACdetect/structure"

// 扫描使用的账户至少所需要的权限：Pods(list、`get`)、ClusterRoleBinding(list 用于收集SA名与Role名)、RoleBinding(全空间list)、sa(全空间get 用于查看挂载属性，由于默认都是挂载的，所以没有该权限一般也可以)、
// ClusterRole(get 用于查看权限verb)、Role(全空间get)、Nodes(list 用于Patch时寻找其余正常节点)
var AdminCert = ""
var AdminCertKey = ""
var ApiServer = ""
var TokenFile = ""
var Kubeconfig = ""
var ProxyAddress = ""
var SSH structure.SSHConfig
