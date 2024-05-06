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
	//Update
	if strings.Contains(k, "(") {
		criticalSA.ResourceName = strings.Trim(k[strings.Index(k, "("):], "()")
	}
	if strings.Contains(k, "[") {
		criticalSA.Namespace = strings.Trim(k[strings.Index(k, "["):], "[]")
	}
	return result
}

func ReadRemoteFile(host string, port int, username, password, pribateKeyFile string, filePath string) (string, error) {
	// SSH configuration information of the remote host
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

	// Connect to remote host
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), sshConfig)
	if err != nil {
		return "", fmt.Errorf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Open a new SSH session
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("Failed to create session: %v", err)
	}
	defer session.Close()

	// Execute remote commands and read file contents
	output, err := session.CombinedOutput("cat " + filePath)
	if err != nil {
		return "", fmt.Errorf("Failed to execute command: %v", err)
	}

	// Return file content
	return string(output), nil
}
