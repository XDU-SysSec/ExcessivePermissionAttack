package structure

type Pod struct {
	Namespace      string
	Name           string
	Uid            string
	NodeName       string
	ServiceAccount string   //SaName
	ControllBy     []string //type
	TokenMounted   bool
}
type SA struct {
	IsMounted    bool
	Name         string //全称: namespace/name
	SAPod        Pod
	Permission   map[string][]string // map[string]map[string][]string
	Roles        map[string]map[string][]string
	RoleBindings []string
}
type CriticalSA struct {
	InNode       bool     //相应Pod是否在node1中
	Type         []string //高权限类型
	Level        string   //cluster、namespace
	SA0          SA
	Namespace    string
	ResourceName string
	Roles        []string
}
type CriticalSAWrapper struct {
	Crisa CriticalSA
	Type  string
}
type RoleBinding struct {
	Namespace string
	Name      string
	RoleRef   string
	Subject   []string
}

type Role struct {
	namespace string
	name      string
	rules     Rule
}

type Rule struct {
	// deployments deployments(coredns)
	Resourcs []string
	Verbs    []string
}

type SAtoken struct {
	SaName         string `json:"name"`
	PermissionType string `json:"type"`
	Token          string `json:"token"`
}

type CriticalSASet struct {
	TokenSet []string
}

type SSHConfig struct {
	Ip             string
	Port           int
	Username       string
	Password       string
	PrivateKeyFile string
	Nodename       string
}
