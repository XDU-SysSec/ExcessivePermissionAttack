package utils

import (
	"fmt"
	"io/ioutil"
	"k8sRBACdetect/structure"
	"strings"

	"golang.org/x/crypto/ssh"
)

func Contains(arr []string, target string) bool {
	for _, s := range arr {
		if s == target {
			return true
		}
	}
	return false
}

func CheckRestrict(k string, rawType string, criticalSA *structure.CriticalSA) string {
	result := rawType
	if strings.Contains(k, "(") {
		result = rawType + k[strings.Index(k, "("):]
	} else if strings.Contains(k, "[") {
		result = rawType + k[strings.Index(k, "["):]
	} else {
		criticalSA.Level = "cluster"
	}
	//更新
	if strings.Contains(k, "(") {
		criticalSA.ResourceName = strings.Trim(k[strings.Index(k, "("):], "()")
	}
	if strings.Contains(k, "[") {
		criticalSA.Namespace = strings.Trim(k[strings.Index(k, "["):], "[]")
	}
	return result
}

func ReadRemoteFile(host string, port int, username, password, pribateKeyFile string, filePath string) (string, error) {
	// 远程主机的 SSH 配置信息
	sshConfig := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if pribateKeyFile != "" {
		privateKeyBytes, err := ioutil.ReadFile(pribateKeyFile)
		if err != nil {
			return "", err
		}
		privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
		sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(privateKey)}

	} else {
		sshConfig.Auth = []ssh.AuthMethod{ssh.Password(password)}
	}

	// 连接到远程主机
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), sshConfig)
	if err != nil {
		return "", fmt.Errorf("Failed to dial: %v", err)
	}
	defer client.Close()

	// 打开一个新的 SSH 会话
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("Failed to create session: %v", err)
	}
	defer session.Close()

	// 执行远程命令，读取文件内容
	output, err := session.CombinedOutput("cat " + filePath)
	if err != nil {
		return "", fmt.Errorf("Failed to execute command: %v", err)
	}

	// 返回文件内容
	return string(output), nil
}
