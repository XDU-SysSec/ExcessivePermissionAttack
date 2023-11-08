package main

import (
	"fmt"
	"github.com/tidwall/gjson"
	"k8sRBACdetect/kubectl"
	"strings"
)

var SaBindingMap = map[string]map[string][]string{}

// saName namespace/saname
///api/v1/namespaces/kube-system/serviceaccounts/tke-log-agent

func checkSaTokenMounted(saName string) bool {
	names := strings.Split(saName, "/")
	if len(names) != 2 {
		err := fmt.Errorf("Wrong SaName: %s", saName)
		fmt.Println(err)
		return false
	}
	opts := kubectl.K8sRequestOption{
		Api:    "/api/v1/namespaces/" + names[0] + "/serviceaccounts/" + names[1],
		Method: "GET",
	}
	resp, err := kubectl.ApiRequest(opts)
	if err != nil {
		return false
	}
	autoMount := gjson.Get(resp, "automountServiceAccountToken")
	if autoMount.Exists() && autoMount.Bool() == false {
		return false
	}
	return true
}

func setSaBindingMap() {
	clusterrolebindingList := kubectl.GetClusterRoleBindings()
	rolebindingList := kubectl.GetRolesBindings()

	for _, clusterrolebinding := range clusterrolebindingList {
		rules := kubectl.GetRulesFromRole(clusterrolebinding.RoleRef)

		for _, sa := range clusterrolebinding.Subject {
			tokenMounted := checkSaTokenMounted(sa)
			if !tokenMounted {
				continue
			}
			if _, ok := SaBindingMap[sa]; ok != true {
				SaBindingMap[sa] = make(map[string][]string)
			}
			for _, rule := range rules {
				for _, res := range rule.Resourcs {
					if _, ok := SaBindingMap[sa][res]; ok != true {
						SaBindingMap[sa][res] = make([]string, 0)
					}
					for _, verb := range rule.Verbs {
						SaBindingMap[sa][res] = append(SaBindingMap[sa][res], verb)
					}
				}
			}
		}
	}

	for _, rolebinding := range rolebindingList {
		rules := kubectl.GetRulesFromRole(rolebinding.RoleRef)
		for _, sa := range rolebinding.Subject {
			if _, ok := SaBindingMap[sa]; ok != true {
				SaBindingMap[sa] = make(map[string][]string)
			}
			for _, rule := range rules {
				for _, res := range rule.Resourcs {
					if _, ok := SaBindingMap[sa][res]; ok != true {
						SaBindingMap[sa][res] = make([]string, 0)
					}
					for _, verb := range rule.Verbs {
						SaBindingMap[sa][res] = append(SaBindingMap[sa][res], verb)
					}
				}
			}
		}
	}
}

func main() {
	setSaBindingMap()

	pods, err := kubectl.GetPods()
	if err != nil {
		fmt.Println("[Get pods] failed: ", err.Error())
	}

	//fmt.Println("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
	//fmt.Println("%%%%%%%%%%        DaemonSet:       %%%%%%%%%%")
	//fmt.Println("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
	for _, pod := range pods {
		//if pod.ControllBy != nil {
		//for _, controller := range pod.ControllBy {
		//	if strings.ToLower(controller) == "daemonset" {
		sa := pod.Namespace + "/" + pod.ServiceAccount
		fmt.Printf("podName: %s sa: %s controllby: %s\n", pod.Namespace+"/"+pod.Name, sa, pod.ControllBy)
		if pod.TokenMounted == false {
			fmt.Println("[x] SA token not mounted")
			continue
		}
		if rules, ok := SaBindingMap[sa]; ok {
			for resource, verbs := range rules {
				fmt.Print(resource, ": ")
				fmt.Println(verbs)
			}
		}
		fmt.Println("------------------------------------")
		//break
		//	}
		//}
		//}
	}
}
