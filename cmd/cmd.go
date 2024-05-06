package cmd

import (
	"fmt"
	"k8sRBACdetect/conf"
	exp "k8sRBACdetect/pkg/exploit"
	scan "k8sRBACdetect/pkg/scan"
	structure "k8sRBACdetect/structure"
	"reflect"
	"sort"
	"strings"
)

var (
	ssh          structure.SSHConfig
	criticalSAs  []structure.CriticalSA
	saBindingMap map[string]*structure.SA
)

func Main() {
	ssh = conf.SSH
	operation := ""
	for {
		fmt.Print("[scan/exp/help] Input the operation: ")
		fmt.Scan(&operation)
		switch operation {
		case "scan":
			{
				if len(saBindingMap) == 0 {
					saBindingMap = scan.GetSaBinding2()
				}
				if len(criticalSAs) == 0 {
					criticalSAs = scan.GetCriticalSA(scan.NewGetSA2(saBindingMap), ssh.Nodename)
				}
				fmt.Println()
				for _, criticalSA := range criticalSAs {
					if !criticalSA.SA0.IsMounted {
						continue
					}
					fmt.Println("[app]:", criticalSA.SA0.SAPod.Namespace)
					fmt.Println("[component]:", criticalSA.SA0.SAPod.Name)
					fmt.Println("[SA]:", criticalSA.SA0.Name)
					fmt.Println("[permission]:", criticalSA.Type)
					fmt.Println("[node]:", criticalSA.SA0.SAPod.NodeName)
					fmt.Println("[roles/clusterRoles]:", criticalSA.Roles)
					fmt.Println("[roleBindings]:", criticalSA.SA0.RoleBindings)
					fmt.Println("-------------------------------------------")
					fmt.Println()
				}

			}
		case "exp":
			{
				exploit(classify(ssh.Nodename), ssh.Nodename, false)
			}
		case "getsa":
			{
				fmt.Scan(&operation)
				if len(saBindingMap) == 0 {
					saBindingMap = scan.GetSaBinding2()
				}
				for sa, permission := range saBindingMap {
					if strings.Contains(sa, operation) {
						fmt.Println("--------------------------------")
						fmt.Println(">>>>>", "account"+sa+"permissions", "<<<<<")
						for res, verb := range permission.Permission {
							fmt.Println("\t", res, "-->", verb)
						}
						break
					}
				}
				fmt.Println()
			}
		case "getsas":
			{
				if len(saBindingMap) == 0 {
					saBindingMap = scan.GetSaBinding2()
				}
				for sa, permission := range saBindingMap {
					fmt.Println("--------------------------------")
					fmt.Println(">>>>>", "account"+sa+"permissions", "<<<<<")
					for res, verb := range permission.Permission {
						fmt.Println("\t", res, "-->", verb)
					}
					fmt.Println("")
				}
			}
		case "help":
			{

			}
		}
	}

}

func classify(ControledNode string) map[string][]SA_sort {
	/*
		{
			"escalate": [{"any": CriticalSA},{"restrict: CriticalSA"},...],
			"hijack": [{},{}],
		}
	*/
	result := make(map[string][]SA_sort, 0)
	kind := map[string]string{
		//createrolebinding*2、patchrolebinding*2、patchrole*2
		"impersonate": "anyescalate", "createclusterrolebindings": "anyescalate", "patchclusterroles": "anyescalate", "createtokens": "anyescalate", "createpods": "anyescalate", "createpodcontrollers": "anyescalate", "patchpodcontrollers": "anyescalate", "createwebhookconfig": "anyescalate", "patchwebhookconfig": "anyescalate",
		"createrolebindings": "restrictescalate", "patchclusterrolebindings": "restrictescalate", "patchrolebindings": "restrictescalate", "patchroles": "restrictescalate", "createsecrets": "restrictescalate", "getsecrets": "restrictescalate", "execpods": "restrictescalate", "execpods2": "restrictescalate", "patchpods": "restrictescalate", "watchsecrets": "restrictescalate",
		"patchnodes": "anyhijack", "deletenodes": "anyhijack", "deletepods": "restricthijack", "createpodeviction": "restricthijack",
	}
	replacements := map[string]string{
		"daemonsets": "podcontrollers", "deployments": "podcontrollers", "statefulsets": "podcontrollers", "replicasets": "podcontrollers", "jobs": "podcontrollers", "cronjobs": "podcontrollers", "replicationcontrollers": "podcontrollers",
		"mutatingwebhookconfigurations": "webhookconfig", "validatingwebhookconfigurations": "webhookconfig",
	}
	if len(saBindingMap) == 0 {
		saBindingMap = scan.GetSaBinding2()
	}
	if len(criticalSAs) == 0 {
		criticalSAs = scan.GetCriticalSA(scan.NewGetSA2(saBindingMap), ssh.Nodename)
	}
	// if len(criticalSAs) == 0 {
	// 	criticalSAs = scan.GetCriticalSA(scan.GetSA(scan.GetSaBinding()), ssh.Nodename)
	// }
	criticalSAsWrappers := []structure.CriticalSAWrapper{}
	for _, criticalSA := range criticalSAs {
		for _, criticalSAType := range criticalSA.Type {
			criticalSAsWrapper := structure.CriticalSAWrapper{
				Crisa: criticalSA,
				Type:  criticalSAType,
			}
			criticalSAsWrappers = append(criticalSAsWrappers, criticalSAsWrapper)
		}
	}

	for _, criticalSA := range criticalSAsWrappers {
		if !criticalSA.Crisa.InNode || !criticalSA.Crisa.SA0.IsMounted {
			continue
		}
		kindType := criticalSA.Type //reduce the rawType
		if strings.Contains(criticalSA.Type, "(") {
			kindType = kindType[:strings.Index(kindType, "(")]
		} else if strings.Contains(criticalSA.Type, "[") {
			kindType = kindType[:strings.Index(kindType, "[")]
		}
		dispatchfunc := kindType
		for old, new := range replacements {
			dispatchfunc = strings.Replace(dispatchfunc, old, new, -1)
		}
		newResult := SA_sort{Level: kind[dispatchfunc] + "-" + criticalSA.Type, SA: criticalSA, dispatchFunc: dispatchfunc}
		tmpType := ""
		if strings.Contains(kind[dispatchfunc], "escalate") {
			tmpType = "escalate"
		} else if strings.Contains(kind[dispatchfunc], "hijack") {
			tmpType = "hijack"
		} else if strings.Contains(kind[dispatchfunc], "dos") {
			tmpType = "dos"
		}
		if criticalSA.Crisa.Level == "namespace" && !strings.Contains(criticalSA.Type, "kube-system") {
			//newResult = map[string]structure.CriticalSA{"restrict" + tmpType + "-" + criticalSA.Type: criticalSA} //In the case of restrictions, existing restrictions are listed to provide options.
			newResult = SA_sort{Level: "restrict" + tmpType + "-" + criticalSA.Type, SA: criticalSA, dispatchFunc: dispatchfunc}
		}
		// if newResult.SA.InNode {
		// 	result[tmpType] = append(result[tmpType], newResult)
		// }
		result[tmpType] = append(result[tmpType], newResult)
	}
	for k, _ := range result {
		sort.Slice(result[k], func(i, j int) bool {
			return result[k][i].Level < result[k][j].Level
		})
	}

	return result
}

func exploit(payloads map[string][]SA_sort, ControledNode string, hijacked bool) {
	anyescalateMap := make(map[int]SA_sort)
	cnt := 0
	for _, sa := range payloads["escalate"] {
		if strings.Contains(sa.Level, "any") {
			if cnt == 0 {
				fmt.Println("[√] privilege escalation. The available permissions are as follows:")
				fmt.Println("---------------------------")
			}
			fmt.Println(cnt, sa.SA.Type, "use SA:", sa.SA.Crisa.SA0.Name)
			anyescalateMap[cnt] = sa
			cnt++
		}
	}
	if len(anyescalateMap) != 0 {
		var choice int
		fmt.Println("---------------------------")
		fmt.Print("[input] Choose a privilege escalation type: ")
		fmt.Scan(&choice)
		fmt.Println("[msg] Coming soon", "account"+anyescalateMap[choice].SA.Crisa.SA0.Name, "(permissions"+anyescalateMap[choice].SA.Type+")", "Perform privilege escalation")
		dispatch(anyescalateMap[choice].SA.Crisa, anyescalateMap[choice].dispatchFunc)
		return
	}
	if hijacked {
		if len(payloads["escalate"]) == 0 {
			fmt.Println("[X] No available privilege escalation detected")
			return
		}
		fmt.Println("[!] Still unable to arbitrarily escalate privileges")
		fmt.Println("[msg] Prepare a list of some of the privilege escalations that can be made")
		fmt.Println("---------------------------")
		escalateMap := make(map[int]SA_sort)
		cnt := 0
		for _, sa := range payloads["escalate"] {
			fmt.Println(cnt, sa.SA.Type, sa.SA.Crisa.SA0.Name)
			escalateMap[cnt] = sa
			cnt++
		}
		fmt.Println("---------------------------")
		fmt.Print("[input] Choose a privilege escalation type: ")
		var choice int
		fmt.Scan(&choice)
		fmt.Println("[msg] Coming soon", "account"+escalateMap[choice].SA.Crisa.SA0.Name, "(permissions"+escalateMap[choice].SA.Type+")", "Perform privilege escalation")
		dispatch(escalateMap[choice].SA.Crisa, escalateMap[choice].dispatchFunc)
	}

	if !hijacked {
		fmt.Println("[!] Unable to arbitrarily escalate privileges")
		fmt.Println("[msg] Prepare to detect 'hijacking' related permissions")
		hijack(payloads, ControledNode)
		exploit(payloads, ControledNode, true)
	}
}

func hijack(payloads map[string][]SA_sort, ControledNode string) bool {
	if len(payloads["hijack"]) == 0 {
		fmt.Println("[!] No 'hijack' related permissions detected")
		return false
	}
	anyhijackMap := make(map[int]SA_sort)
	cnt1 := 0
	for _, sa := range payloads["hijack"] {
		if strings.Contains(sa.Level, "any") {
			if cnt1 == 0 {
				fmt.Println("[√] Any component can be hijacked, and the available permissions are as follows::")
				fmt.Println("---------------------------")
			}
			fmt.Println(cnt1, sa.SA.Type, sa.SA.Crisa.SA0.Name)
			anyhijackMap[cnt1] = sa
			cnt1++
		}
	}
	if len(anyhijackMap) != 0 {
		var choice int
		fmt.Println("---------------------------")
		fmt.Print("[input] Choose a privilege escalation type: ")
		fmt.Scan(&choice)
		fmt.Println("[msg] Coming soon", "account"+anyhijackMap[choice].SA.Crisa.SA0.Name, "(permissions"+anyhijackMap[choice].SA.Type+")", "Perform component hijacking")
		dispatch(anyhijackMap[choice].SA.Crisa, anyhijackMap[choice].dispatchFunc)
		return true
	}
	fmt.Println("[!] Only certain components can be hijacked")
	fmt.Println("[msg] Prepare to list specific components that can be hijacked")
	fmt.Println("---------------------------")
	hijackMap := make(map[int]SA_sort)
	cnt2 := 0
	for _, sa := range payloads["hijack"] {
		fmt.Println(cnt2, sa.SA.Type, sa.SA.Crisa.SA0.Name)
		hijackMap[cnt2] = sa
		cnt2++
	}
	fmt.Println("---------------------------")
	fmt.Print("[input] Choose a hijacking type: ")
	var choice int
	fmt.Scan(&choice)
	fmt.Println("[msg] Coming soon", "account"+hijackMap[choice].SA.Crisa.SA0.Name, "(permissions"+hijackMap[choice].SA.Type+")", "Perform component hijacking")
	dispatch(hijackMap[choice].SA.Crisa, hijackMap[choice].dispatchFunc)
	return true
}

func dispatch(sa structure.CriticalSA, dispatchFunc string) {
	funcMap := map[string]interface{}{
		"impersonate": exp.Impersonate, "createclusterrolebindings": exp.Createclusterrolebindings, "patchclusterroles": exp.Patchclusterroles, "createtokens": exp.Createtokens, "createpods": exp.Createpods, "createpodcontrollers": exp.Createpodcontrollers, "patchpodcontrollers": exp.Patchpodcontrollers,
		"createrolebindings": exp.Createrolebindings, "patchclusterrolebindings": exp.Patchclusterrolebindings, "patchrolebindings": exp.Patchrolebindings, "patchroles": exp.Patchroles, "createsecrets": exp.Createsecrets, "getsecrets": exp.Getsecrets, "execpods": exp.Execpods, "execpods2": exp.Execpods2, "patchpods": exp.Patchpods,
		"patchnodes": exp.Patchnodes, "deletepods": exp.Deletepods, "createpodeviction": exp.Createpodeviction, "deletenodes": exp.Deletenodes, "watchsecrets": exp.WatchSecrets, "patchwebhookconfig": exp.Patchwebhookconfig, "createwebhookconfig": exp.Createwebhookconfig,
	}
	funcValue := reflect.ValueOf(funcMap[dispatchFunc])
	args := []reflect.Value{reflect.ValueOf([]structure.CriticalSA{sa}), reflect.ValueOf(ssh)}
	//fmt.Println("[msg] About to be called:", strings.Title(sa.Type))
	funcValue.Call(args)
}

type SA_sort struct {
	Level        string                      //Key used to sort by (any, restrict)
	dispatchFunc string                      //key used to call the function
	SA           structure.CriticalSAWrapper //Actual SA information
}
