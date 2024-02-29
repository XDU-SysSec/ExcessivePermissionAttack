package main

import (
	"fmt"
	"k8sRBACdetect/cmd"
	"k8sRBACdetect/conf"
	"k8sRBACdetect/structure"

	"github.com/spf13/viper"
)

func main() {
	cmd.Main()
}
func init() {
	viper.SetConfigFile(".\\conf\\conf.yaml")
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file: %s\n", err)
		return
	}
	conf.ApiServer = viper.GetString("apiServer")
	conf.ProxyAddress = viper.GetString("proxyAddress")

	conf.TokenFile = viper.GetString("auth.0.tokenFile")
	conf.Kubeconfig = viper.GetString("auth.1.kubeconfig")
	conf.AdminCert = viper.GetString("auth.2.crt")
	conf.AdminCert = viper.GetString("auth.2.key")

	var sshConfig structure.SSHConfig
	if err := viper.UnmarshalKey("ssh.0", &sshConfig); err != nil {
		fmt.Printf("Error unmarshalling SSH config: %s\n", err)
		return
	}
	conf.SSH = sshConfig
}
