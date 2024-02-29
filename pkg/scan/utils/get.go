package utils

import (
	"k8sRBACdetect/pkg/request"
	apis "k8sRBACdetect/structure"
	"strings"

	"github.com/tidwall/gjson"
)

func GetPods() ([]apis.Pod, error) {
	opts := request.K8sRequestOption{
		Api:    "/api/v1/pods",
		Method: "GET",
	}
	resp, err := request.ApiRequest(opts)
	if err != nil {
		return nil, err
	}
	pods := gjson.Get(resp, "items").Array()
	podList := make([]apis.Pod, 0)

	for _, pod := range pods {
		newPod := apis.Pod{
			Namespace:      pod.Get("metadata.namespace").String(),
			Name:           pod.Get("metadata.name").String(),
			Uid:            pod.Get("metadata.uid").String(),
			NodeName:       pod.Get("spec.nodeName").String(),
			ServiceAccount: pod.Get("spec.serviceAccountName").String(),
		}
		tokenMounted := pod.Get("spec.automountServiceAccountToken")
		if tokenMounted.Exists() {
			newPod.TokenMounted = tokenMounted.Bool()
		} else {
			newPod.TokenMounted = true
		}

		if pod.Get("metadata.ownerReferences").Exists() {
			newPod.ControllBy = make([]string, 0)
			owners := pod.Get("metadata.ownerReferences").Array()
			for _, owner := range owners {
				newPod.ControllBy = append(newPod.ControllBy, owner.Get("kind").String())
			}
		}

		podList = append(podList, newPod)

	}
	return podList, nil
}

func GetClusterRoleBindings() []apis.RoleBinding {
	// 获取所有 clusterrole
	opts := request.K8sRequestOption{
		Api:    "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
		Method: "GET",
	}
	resp, err := request.ApiRequest(opts)
	if err != nil {
		return nil
	}
	clusterRoleBindings := gjson.Get(resp, "items").Array()
	clusterRoleBindingList := make([]apis.RoleBinding, 0)

	for _, clusterRoleBinding := range clusterRoleBindings {
		newClusterRoleBinding := apis.RoleBinding{
			Namespace: "",
			Name:      clusterRoleBinding.Get("metadata.name").String(),
			RoleRef:   clusterRoleBinding.Get("roleRef.name").String(),
		}
		if clusterRoleBinding.Get("subjects").Exists() {
			for _, sa := range clusterRoleBinding.Get("subjects").Array() {
				if sa.Get("kind").String() != "ServiceAccount" {
					continue
				}
				newClusterRoleBinding.Subject = append(newClusterRoleBinding.Subject, sa.Get("namespace").String()+"/"+sa.Get("name").String())
			}
		}
		clusterRoleBindingList = append(clusterRoleBindingList, newClusterRoleBinding)
	}

	return clusterRoleBindingList
}

func GetRolesBindings() []apis.RoleBinding {
	opts := request.K8sRequestOption{
		Api:    "/apis/rbac.authorization.k8s.io/v1/rolebindings",
		Method: "GET",
	}
	resp, err := request.ApiRequest(opts)
	if err != nil {
		return nil
	}
	roleBindings := gjson.Get(resp, "items").Array()
	roleBindingList := make([]apis.RoleBinding, 0)

	for _, roleBinding := range roleBindings {
		newRoleBinding := apis.RoleBinding{
			Namespace: roleBinding.Get("metadata.namespace").String(),
			Name:      roleBinding.Get("metadata.name").String(),
		}

		roleKind := roleBinding.Get("roleRef.kind").String()
		if roleKind == "Role" {
			newRoleBinding.RoleRef = newRoleBinding.Namespace + "/"
		}
		newRoleBinding.RoleRef += roleBinding.Get("roleRef.name").String()

		if roleBinding.Get("subjects").Exists() {
			for _, sa := range roleBinding.Get("subjects").Array() {
				if sa.Get("kind").String() != "ServiceAccount" {
					continue
				}
				newRoleBinding.Subject = append(newRoleBinding.Subject, sa.Get("namespace").String()+"/"+sa.Get("name").String())
			}
		}
		roleBindingList = append(roleBindingList, newRoleBinding)
	}
	return roleBindingList
}

// rule ==> namespace/name
func GetRulesFromRole(role string) []apis.Rule {
	var namespace, name, api string
	api = "/apis/rbac.authorization.k8s.io/v1"
	if strings.Contains(role, "/") {
		// role
		namespace = role[:strings.Index(role, "/")]
		name = role[strings.Index(role, "/")+1:]
		api += "/namespaces/" + namespace + "/roles/" + name
	} else {
		// clusterrole
		name = role
		api += "/clusterroles/" + name
	}
	opts := request.K8sRequestOption{
		Api:    api,
		Method: "GET",
		//Token:  token,
	}
	resp, err := request.ApiRequest(opts)
	if err != nil {
		return nil
	}
	rules := gjson.Get(resp, "rules").Array()
	ruleList := make([]apis.Rule, 0)
	for _, rule := range rules {
		newRule := apis.Rule{
			Resourcs: make([]string, 0),
			Verbs:    make([]string, 0),
		}
		resources := rule.Get("resources").Array()
		resourceNames := rule.Get("resourceNames")
		for _, res := range resources {
			if resourceNames.Exists() {
				for _, resName := range resourceNames.Array() {
					newRule.Resourcs = append(newRule.Resourcs, res.String()+"("+resName.String()+")")
				}
			} else {
				newRule.Resourcs = append(newRule.Resourcs, res.String())
			}
		}
		verbs := rule.Get("verbs").Array()
		for _, verb := range verbs {
			newRule.Verbs = append(newRule.Verbs, verb.String())
		}
		ruleList = append(ruleList, newRule)
	}

	return ruleList
}
