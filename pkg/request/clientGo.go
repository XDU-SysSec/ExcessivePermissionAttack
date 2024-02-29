package request

import (
	"fmt"
	"io/ioutil"
	"k8sRBACdetect/conf"
	"net/http"
	"net/url"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func GetClientSet(token string) *kubernetes.Clientset {
	config := &rest.Config{}
	if token == "" {
		rawToken, _ := ioutil.ReadFile(conf.TokenFile)
		token = string(rawToken)
		if token == "" {
			config.TLSClientConfig.CertFile = conf.AdminCert
			config.TLSClientConfig.KeyFile = conf.AdminCertKey
		}
	}
	if conf.ProxyAddress != "" {
		proxyURL := conf.ProxyAddress
		proxy := func(_ *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		}
		config.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
			return &http.Transport{
				Proxy: proxy,
				// 可以根据需要进行其他配置
			}
		}
	}
	config.TLSClientConfig.Insecure = true
	if token != "" {
		config.BearerToken = token
	}
	config.Host = "https://" + conf.ApiServer //"https://192.168.183.130:6443"
	// config = &rest.Config{
	// 	BearerToken: token,
	// 	Host:        "https://" + conf.ApiServer, //"https://192.168.183.130:6443"
	// 	TLSClientConfig: rest.TLSClientConfig{
	// 		Insecure: true,
	// 		// CAData: []byte(""), 如果 Insecure: true 未开启，需要 CAData
	// 	},
	// }
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("Error creating kubernetes client: %v\n", err)
	}
	return clientset
}
