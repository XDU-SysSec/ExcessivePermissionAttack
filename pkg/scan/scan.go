package scan

import (
	"fmt"
	utils "k8sRBACdetect/pkg/scan/utils"
	structure "k8sRBACdetect/structure"
	"strings"
)

// Get SAs (SAs mounted in Pod)
func GetSA(saBindingMap map[string]map[string][]string) map[string]*structure.SA {
	// Collect all SAs and their bound Roles
	result := make(map[string]*structure.SA, 0)
	pods, err := utils.GetPods()
	if err != nil {
		fmt.Println("[Get pods] failed: ", err.Error())
	}
	for _, pod := range pods {
		SA := structure.SA{
			Name:       pod.Namespace + "/" + pod.ServiceAccount,
			SAPod:      pod,
			Permission: saBindingMap[pod.Namespace+"/"+pod.ServiceAccount],
		}
		result[pod.Namespace+"/"+pod.ServiceAccount] = &SA
	}

	return result

}

// Get all SAs and mark whether to mount them
func GetSA2(saBindingMap map[string]map[string][]string) map[string]*structure.SA {
	result := make(map[string]*structure.SA, 0)
	for sa, per := range saBindingMap {
		SA := structure.SA{
			Name:       sa,
			Permission: per,
		}
		result[sa] = &SA
	}
	pods, err := utils.GetPods()
	if err != nil {
		fmt.Println("[Get pods] failed: ", err.Error())
	}
	for _, pod := range pods {
		_, exists := result[pod.Namespace+"/"+pod.ServiceAccount]
		if exists {
			result[pod.Namespace+"/"+pod.ServiceAccount].IsMounted = true
			result[pod.Namespace+"/"+pod.ServiceAccount].SAPod = pod
		}

	}
	return result
}

func NewGetSA2(sas map[string]*structure.SA) map[string]*structure.SA {
	result := sas
	pods, err := utils.GetPods()
	if err != nil {
		fmt.Println("[Get pods] failed: ", err.Error())
	}
	for _, pod := range pods {
		_, exists := result[pod.Namespace+"/"+pod.ServiceAccount]
		if exists {
			result[pod.Namespace+"/"+pod.ServiceAccount].IsMounted = true
			result[pod.Namespace+"/"+pod.ServiceAccount].SAPod = pod
		}

	}
	return result
}

// Filter high-privilege SA and mark whether the high-privilege SA is in the controlled node.
func GetCriticalSA(SAs map[string]*structure.SA, ControledNode string) []structure.CriticalSA {
	result := []structure.CriticalSA{}
	for _, sa := range SAs {
		clusterrolebindFlag1 := 0
		clusterrolebindFlag2 := 0
		rolebindFlag1 := 0
		rolebindFlag2 := 0
		clusterroleescalateFlag := 0
		roleescalateFlag := 0
		criticalSA := structure.CriticalSA{
			SA0:    *sa,
			InNode: false,
			Level:  "namespace",
			Type:   []string{},
		}
		for roleName, role := range sa.Roles {
			criticalSA.Roles = append(criticalSA.Roles, roleName)
			for k, v := range role {
				if sa.SAPod.NodeName == ControledNode {
					criticalSA.InNode = true
				}
				rawType := ""
				// if utils.Contains(v, "create") || utils.Contains(v, "*") {
				// 	if strings.Contains(k, "serviceaccounts") || strings.Contains(k, "*") {
				// 		rawType = "createserviceaccounts"
				// 		criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
				// 		result = append(result, criticalSA)
				// 	}
				// }
				if utils.Contains(v, "get") || utils.Contains(v, "*") {
					if strings.Contains(k, "secrets") || strings.Contains(k, "*") {
						rawType = "getsecrets"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
				}
				if utils.Contains(v, "watch") || utils.Contains(v, "*") {
					if strings.Contains(k, "secrets") || strings.Contains(k, "*") {
						rawType = "watchsecrets"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
				}

				if utils.Contains(v, "patch") || utils.Contains(v, "*") {
					if k == "nodes" || k == "*" {
						criticalSA.Type = append(criticalSA.Type, "patchnodes")
					}
					if strings.Contains(k, "clusterroles") || strings.Contains(k, "*") {
						clusterroleescalateFlag++
						if clusterroleescalateFlag == 2 {
							criticalSA.Type = append(criticalSA.Type, "patchclusterroles")
						}
					}
					if strings.Contains(k, "roles") || strings.Contains(k, "*") {
						roleescalateFlag++
						if roleescalateFlag == 2 {
							rawType = "patchroles"
							criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
						}
					}
					if strings.Contains(k, "clusterrolebindings") || strings.Contains(k, "*") {
						clusterrolebindFlag2++
						if clusterrolebindFlag2 == 2 {
							criticalSA.Type = append(criticalSA.Type, "patchclusterrolebindings")
						}
					}
					if strings.Contains(k, "rolebindings") || strings.Contains(k, "*") {
						rolebindFlag2++
						if rolebindFlag2 == 2 {
							rawType = "patchrolebindings"
							criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
						}
					}
					if strings.Contains(k, "pods") || strings.Contains(k, "*") {
						rawType = "patchpods"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "daemonsets") || strings.Contains(k, "*") {
						rawType = "patchdaemonsets"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "deployments") || strings.Contains(k, "*") { // * of patchPodController are unified into Deployment.
						rawType = "patchdeployments"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "statefulsets") || strings.Contains(k, "*") {
						rawType = "patchstatefulsets"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "replicasets") || strings.Contains(k, "*") {
						rawType = "patchreplicasets"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "cronjobs") || strings.Contains(k, "*") {
						rawType = "patchcronjobs"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					} else if strings.Contains(k, "jobs") || strings.Contains(k, "*") {
						rawType = "patchjobs"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "replicationcontrollers") || strings.Contains(k, "*") {
						rawType = "patchreplicationcontrollers"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}

					if strings.Contains(k, "mutatingwebhookconfigurations") || k == "*" {
						criticalSA.Type = append(criticalSA.Type, "patchmutatingwebhookconfigurations")
					}
					if strings.Contains(k, "validatingwebhookconfigurations") || k == "*" {
						criticalSA.Type = append(criticalSA.Type, "patchvalidatingwebhookconfigurations")
					}
				}

				if utils.Contains(v, "create") || utils.Contains(v, "*") {
					if strings.Contains(k, "secrets") || strings.Contains(k, "*") {
						rawType = "createsecrets"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "clusterrolebindings") || strings.Contains(k, "*") {
						clusterrolebindFlag1++
						if clusterrolebindFlag1 == 2 {
							criticalSA.Type = append(criticalSA.Type, "createclusterrolebindings")
						}
					}
					if strings.Contains(k, "rolebindings") || strings.Contains(k, "*") {
						rolebindFlag1++
						if rolebindFlag1 == 2 {
							rawType = "createrolebindings"
							criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
						}
					}
					if strings.Contains(k, "serviceaccounts/token") || strings.Contains(k, "*") {
						rawType = "createtokens"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "pods") || strings.Contains(k, "*") {
						rawType = "createpods"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "pods/exec") || strings.Contains(k, "*") {
						rawType = "execpods"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "pods/ephemeralcontainers") || strings.Contains(k, "*") {
						rawType = "execpods2"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "daemonsets") || strings.Contains(k, "*") {
						rawType = "createdaemonsets"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "deployments") || strings.Contains(k, "*") {
						rawType = "createdeployments"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "statefulsets") || strings.Contains(k, "*") {
						rawType = "createstatefulsets"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "replicasets") || strings.Contains(k, "*") {
						rawType = "createreplicasets"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "cronjobs") || strings.Contains(k, "*") {
						rawType = "createcronjobs"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					} else if strings.Contains(k, "jobs") || strings.Contains(k, "*") {
						rawType = "createjobs"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "replicationcontrollers") || strings.Contains(k, "*") {
						rawType = "createreplicationcontrollers"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "mutatingwebhookconfigurations") || strings.Contains(k, "*") {
						criticalSA.Type = append(criticalSA.Type, "createmutatingwebhookconfigurations")
					}
					if strings.Contains(k, "validatingwebhookconfigurations") || strings.Contains(k, "*") {
						criticalSA.Type = append(criticalSA.Type, "createvalidatingwebhookconfigurations")
					}
					if strings.Contains(k, "nodes") || strings.Contains(k, "*") {
						criticalSA.Type = append(criticalSA.Type, "createnodes")
					}

				}

				if utils.Contains(v, "bind") || utils.Contains(v, "*") {
					if strings.Contains(k, "clusterroles") || strings.Contains(k, "*") {
						clusterrolebindFlag1++
						clusterrolebindFlag2++
						if clusterrolebindFlag1 == 2 {
							criticalSA.Type = append(criticalSA.Type, "createclusterrolebindings")
						}
						if clusterrolebindFlag2 == 2 {
							criticalSA.Type = append(criticalSA.Type, "patchclusterrolebindings")
						}
					}
					if strings.Contains(k, "roles") || strings.Contains(k, "*") {
						rolebindFlag1++
						rolebindFlag2++
						if rolebindFlag1 == 2 {
							rawType = "createrolebindings"
							criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
						}
						if rolebindFlag2 == 2 {
							rawType = "patchrolebindings"
							criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
						}

					}
				}

				if utils.Contains(v, "delete") || utils.Contains(v, "*") {
					if strings.Contains(k, "pods") || strings.Contains(k, "*") {
						rawType = "deletepods"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))

					}
					if strings.Contains(k, "nodes") || strings.Contains(k, "*") {
						rawType = "deletenodes"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}
					if strings.Contains(k, "validatingwebhookconfigurations") || strings.Contains(k, "*") {
						rawType = "deletevalidatingwebhookconfigurations"
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
					}

					//criticalSA.Type = append(criticalSA.Type, "delete"+k)
				}

				if utils.Contains(v, "escalate") || utils.Contains(v, "*") {
					if strings.Contains(k, "clusterroles") || strings.Contains(k, "*") {
						clusterroleescalateFlag++
						if clusterroleescalateFlag == 2 {
							criticalSA.Type = append(criticalSA.Type, "patchclusterroles")
						}
					}
					if strings.Contains(k, "roles") || strings.Contains(k, "*") {
						roleescalateFlag++
						if roleescalateFlag == 2 {
							rawType = "patchroles"
							criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(k, rawType, &criticalSA))
						}
					}
				}

				if utils.Contains(v, "impersonate") {
					criticalSA.Type = append(criticalSA.Type, "impersonate")
				}

				if utils.Contains(v, "update") {
					criticalSA.Type = append(criticalSA.Type, "update"+k)
				}
			}

		}
		if len(criticalSA.Type) != 0 {
			result = append(result, criticalSA)
		}

	}
	return result
}

// Get SAs (all, whether mounted in the Pod or not)
func GetSaBinding() map[string]map[string][]string {
	var SaBindingMap = map[string]map[string][]string{}
	clusterrolebindingList := utils.GetClusterRoleBindings()
	rolebindingList := utils.GetRolesBindings()
	for _, clusterrolebinding := range clusterrolebindingList {
		rules := utils.GetRulesFromRole(clusterrolebinding.RoleRef)
		for _, sa := range clusterrolebinding.Subject {
			//tokenMounted := utils.CheckSaTokenMounted(sa)
			// if !tokenMounted {
			// 	fmt.Print("%s noMounted", sa)
			// 	continue
			// }
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
		rules := utils.GetRulesFromRole(rolebinding.RoleRef)
		for _, sa := range rolebinding.Subject {
			if _, ok := SaBindingMap[sa]; ok != true {
				SaBindingMap[sa] = make(map[string][]string)
			}
			for _, rule := range rules {
				for _, res := range rule.Resourcs {
					res = res + "[" + rolebinding.Namespace + "]" // Pod(pod1)[default]
					if _, ok := SaBindingMap[sa][res]; ok != true {
						SaBindingMap[sa][res] = make([]string, 0)
					}
					for _, verb := range rule.Verbs {
						SaBindingMap[sa][res] = append(SaBindingMap[sa][res], verb) //+"["+rolebinding.Namespace+"]"
					}
				}
			}
		}
	}
	return SaBindingMap
}

func GetSaBinding2() map[string]*structure.SA {
	var SaBindingMap = map[string]map[string][]string{}
	var result map[string]*structure.SA
	result = make(map[string]*structure.SA)
	clusterrolebindingList := utils.GetClusterRoleBindings()
	rolebindingList := utils.GetRolesBindings()
	for _, clusterrolebinding := range clusterrolebindingList {
		rules := utils.GetRulesFromRole(clusterrolebinding.RoleRef)
		for _, sa := range clusterrolebinding.Subject {
			//tokenMounted := utils.CheckSaTokenMounted(sa)
			// if !tokenMounted {
			// 	fmt.Print("%s noMounted", sa)
			// 	continue
			// }
			if _, ok := SaBindingMap[sa]; ok != true {
				SaBindingMap[sa] = make(map[string][]string)
			}
			if _, ok := result[sa]; ok != true {
				result[sa] = &structure.SA{
					Name:         sa,
					RoleBindings: []string{},
					Roles:        map[string]map[string][]string{},
				}
			}
			result[sa].RoleBindings = append(result[sa].RoleBindings, clusterrolebinding.Name)
			for _, rule := range rules {
				for _, res := range rule.Resourcs {
					if _, ok := result[sa].Roles[clusterrolebinding.RoleRef]; ok != true {
						result[sa].Roles[clusterrolebinding.RoleRef] = make(map[string][]string, 0)
					}
					for _, verb := range rule.Verbs {
						result[sa].Roles[clusterrolebinding.RoleRef][res] = append(result[sa].Roles[clusterrolebinding.RoleRef][res], verb)
						SaBindingMap[sa][res] = append(SaBindingMap[sa][res], verb)
					}
				}
			}
			result[sa].Permission = SaBindingMap[sa]
		}
	}

	for _, rolebinding := range rolebindingList {
		rules := utils.GetRulesFromRole(rolebinding.RoleRef)
		for _, sa := range rolebinding.Subject {
			if _, ok := SaBindingMap[sa]; ok != true {
				SaBindingMap[sa] = make(map[string][]string)
			}
			if _, ok := result[sa]; ok != true {
				result[sa] = &structure.SA{
					Name:         sa,
					RoleBindings: []string{},
					Roles:        map[string]map[string][]string{},
				}
			}
			result[sa].RoleBindings = append(result[sa].RoleBindings, rolebinding.Name)
			for _, rule := range rules {
				for _, res := range rule.Resourcs {
					res = res + "[" + rolebinding.Namespace + "]" // Pod(pod1)[default]
					if _, ok := result[sa].Roles[rolebinding.RoleRef]; ok != true {
						result[sa].Roles[rolebinding.RoleRef] = make(map[string][]string, 0)
					}
					for _, verb := range rule.Verbs {
						result[sa].Roles[rolebinding.RoleRef][res] = append(result[sa].Roles[rolebinding.RoleRef][res], verb)
						SaBindingMap[sa][res] = append(SaBindingMap[sa][res], verb) //+"["+rolebinding.Namespace+"]"
					}
				}
			}
			result[sa].Permission = SaBindingMap[sa]
		}
	}
	return result
}

//ClusterRole1: res

// Get the token of the specified SA in the controlled node.
func GetCriticalSAToken(sa structure.CriticalSA, ssh structure.SSHConfig) (string, error) { //  /var/lib/kubelet/pods
	filePath := "/var/lib/kubelet/pods/" + sa.SA0.SAPod.Uid + "/volumes/kubernetes.io*/*/token"
	token, err := utils.ReadRemoteFile(ssh.Ip, ssh.Port, ssh.Username, ssh.Password, ssh.PrivateKeyFile, filePath)
	if err != nil {
		return "", err
	} else {
		return token, nil
	}
	// Local file reading
	// fmt.Print("[msg] useCriticalSa: ", sa, "\n\n")
	// pattern := "/var/lib/kubelet/pods/" + sa.SA0.SAPod.Uid + "/volumes/kubernetes.io*/*/token"
	// matches, err := filepath.Glob(pattern)
	// if err != nil {
	// 	fmt.Println("An error occurred while locating the file:", err)
	// 	return ""
	// }
	// if len(matches) == 0 {
	// 	fmt.Println("No files matched.")
	// 	return ""
	// }
	// filePath := matches[0]
	// //fmt.Println(filePath)
	// fileContents, err := ioutil.ReadFile(filePath)
	// if err != nil {
	// 	fmt.Println("Unable to read file contents:", err)
	// 	return ""
	// }

	// return string(fileContents)
}
