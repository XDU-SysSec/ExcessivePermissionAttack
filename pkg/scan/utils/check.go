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
	//SA is mounted by default, that is, if this attribute exists and the value is false, it is not mounted.
	//If there is no such attribute and the value is true, it is mounted.
	if autoMount.Exists() && autoMount.Bool() == false { 
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
