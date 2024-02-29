package cmd

import (
	"fmt"
	"k8sRBACdetect/conf"
	exp "k8sRBACdetect/pkg/exploit"
	scan "k8sRBACdetect/pkg/scan"
	"k8sRBACdetect/structure"
	"reflect"
	"strings"
)

var (
	ssh2 structure.SSHConfig
)

func Main1() {
	ControledNode := ssh2.Nodename
	var saBindingMap map[string]map[string][]string
	var criticalSAs []structure.CriticalSA
	ssh2 = conf.SSH
	for {
		var cmd string
		fmt.Print("> ")
		fmt.Scan(&cmd)
		cmd = strings.ToUpper(cmd)
		if cmd == "SCAN" {
			if len(saBindingMap) == 0 {
				saBindingMap = scan.GetSaBinding()
			}
			if len(criticalSAs) == 0 {
				criticalSAs = scan.GetCriticalSA(scan.GetSA2(saBindingMap), ControledNode)
			}
			criticalSAs = scan.GetCriticalSA(scan.NewGetSA2(scan.GetSaBinding2()), ControledNode)
			fmt.Println("[√] 扫描获取已挂载的风险SA")
			for _, criticalSA := range criticalSAs {
				if criticalSA.SA0.IsMounted {
					fmt.Println(criticalSA.SA0.SAPod.ServiceAccount+": ", criticalSA.Type, " (位于"+criticalSA.SA0.SAPod.NodeName+")", criticalSA.Roles)
					fmt.Println("--------------------------------------")
				}
			}

		} else if cmd == "SCAN2" {
			if len(saBindingMap) == 0 {
				saBindingMap = scan.GetSaBinding()
			}
			if len(criticalSAs) == 0 {
				criticalSAs = scan.GetCriticalSA(scan.GetSA2(saBindingMap), ControledNode)
			}
			criticalSAs = scan.GetCriticalSA(scan.NewGetSA2(scan.GetSaBinding2()), ControledNode)
			fmt.Println("[√] 扫描获取未挂载的风险SA")
			for _, criticalSA := range criticalSAs {
				if !criticalSA.SA0.IsMounted {
					fmt.Println(criticalSA.SA0.Name+": ", criticalSA.Type, "(notMount)")
				}
			}
		} else if cmd == "GETSAS" {
			if len(saBindingMap) == 0 {
				saBindingMap = scan.GetSaBinding()
			}
			for sa, permission := range saBindingMap {
				fmt.Println("--------------------------------")
				fmt.Println(">>>>>", "账户"+sa+"权限", "<<<<<")
				for res, verb := range permission {
					fmt.Println("\t", res, "-->", verb)
				}
				fmt.Println("")
			}

		} else if cmd == "GETSA" {
			fmt.Scan(&cmd)
			if len(saBindingMap) == 0 {
				saBindingMap = scan.GetSaBinding()
			}
			for sa, permission := range saBindingMap {
				if strings.Contains(sa, cmd) {
					fmt.Println("--------------------------------")
					fmt.Println(">>>>>", "账户"+sa+"权限", "<<<<<")
					for res, verb := range permission {
						fmt.Println("\t", res, "-->", verb)
					}
					break
				}
			}
			fmt.Println()

		} else {
			if len(saBindingMap) == 0 {
				saBindingMap = scan.GetSaBinding()
			}
			if len(criticalSAs) == 0 {
				criticalSAs = scan.GetCriticalSA(scan.GetSA2(saBindingMap), ControledNode)
			}
			dispatch2(criticalSAs, cmd)
		}
	}
}

func dispatch2(sa []structure.CriticalSA, cmd string) {
	funcMap := map[string]interface{}{
		"impersonate": exp.Impersonate, "createclusterrolebindings": exp.Createclusterrolebindings, "patchclusterroles": exp.Patchclusterroles, "createtokens": exp.Createtokens, "createpods": exp.Createpods, "createpodcontrollers": exp.Createpodcontrollers, "patchpodcontrollers": exp.Patchpodcontrollers,
		"createrolebindings": exp.Createrolebindings, "patchclusterrolebindings": exp.Patchclusterrolebindings, "patchrolebindings": exp.Patchrolebindings, "patchroles": exp.Patchroles, "createsecrets": exp.Createsecrets, "getsecrets": exp.Getsecrets, "execpods": exp.Execpods, "execpods2": exp.Execpods2, "patchpods": exp.Patchpods,
		"patchnodes": exp.Patchnodes, "deletepods": exp.Deletepods, "createpodeviction": exp.Createpodeviction, "deletenodes": exp.Deletenodes,
	}
	funcValue := reflect.ValueOf(funcMap[strings.ToLower(cmd)])
	args := []reflect.Value{reflect.ValueOf(sa), reflect.ValueOf(ssh2)}
	//fmt.Println("[msg] 即将调用:", strings.Title(sa.Type))
	funcValue.Call(args)
}
