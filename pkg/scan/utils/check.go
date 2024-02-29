package utils

import (
	"fmt"
	"k8sRBACdetect/pkg/request"
	"k8sRBACdetect/structure"
	"strings"

	"github.com/tidwall/gjson"
)

func CheckSaTokenMounted(saName string) bool {
	names := strings.Split(saName, "/")
	if len(names) != 2 {
		err := fmt.Errorf("Wrong SaName: %s", saName)
		fmt.Println(err)
		return false
	}
	opts := request.K8sRequestOption{
		Api:    "/api/v1/namespaces/" + names[0] + "/serviceaccounts/" + names[1],
		Method: "GET",
	}
	resp, err := request.ApiRequest(opts)
	if err != nil {
		return false
	}
	//fmt.Print(resp)
	autoMount := gjson.Get(resp, "automountServiceAccountToken")
	if autoMount.Exists() && autoMount.Bool() == false { //默认挂载SA，即存在该属性且值为false才为不挂载，没有该属性和有该属性且值为true均为挂载
		return false
	}
	return true
}

func CheckPatch(criticalSA *structure.CriticalSA, ControledNode string) {
	opts := request.K8sRequestOption{
		Api:    "/api/v1/pods",
		Method: "GET",
	}
	resp, _ := request.ApiRequest(opts)
	pods := gjson.Get(resp, "items").Array()
	for _, pod := range pods {
		if pod.Get("metadata.name").String() == criticalSA.SA0.SAPod.Name {
			criticalSA.SA0.SAPod.NodeName = pod.Get("spec.nodeName").String()
		}
	}

	if ControledNode == criticalSA.SA0.SAPod.NodeName {
		criticalSA.InNode = true
	}

}
