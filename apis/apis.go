package apis

type Pod struct {
	Namespace      string
	Name           string
	ServiceAccount string
	ControllBy     []string
	TokenMounted   bool
}

type ServiceAccount struct {
	namespace string
	name      string
	roles     []Role
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
	rules     []Rule
}

type Rule struct {
	// deployments deployments(coredns)
	Resourcs []string
	Verbs    []string
}
