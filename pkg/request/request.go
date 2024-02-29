package request

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"k8sRBACdetect/conf"
	"net/http"
	netUrl "net/url"
	"strings"
)

type K8sRequestOption struct {
	Token    string
	cert     string
	key      string
	Server   string
	Api      string
	Method   string
	PostData string
	Header   map[string]string
}

func ApiRequest(opts K8sRequestOption) (string, error) {
	if opts.Server == "" {
		opts.Server = conf.ApiServer
	}
	opts.Method = strings.ToUpper(opts.Method)
	url := "https://" + opts.Server + opts.Api
	var client *http.Client
	client = &http.Client{}
	request, err := http.NewRequest(opts.Method, url, bytes.NewBuffer([]byte(opts.PostData)))
	for key, value := range opts.Header {
		request.Header.Set(key, value)
	}

	if err != nil {
		return "", err
	}

	//优先级: opts.token => token文件 => cert文件
	tokenBytes, _ := ioutil.ReadFile(conf.TokenFile)
	var cert tls.Certificate
	if opts.Token != "" {
	} else if string(tokenBytes) != "" {
		opts.Token = string(tokenBytes)
	} else if opts.Token == "" {
		if opts.cert == "" {
			opts.cert = conf.AdminCert
		}
		if opts.key == "" {
			opts.key = conf.AdminCertKey
		}
		cert, err = tls.LoadX509KeyPair(opts.cert, opts.key)
		if err != nil {
			return "", err
		}
	}
	if conf.ProxyAddress != "" {
		proxyURL, _ := netUrl.Parse(conf.ProxyAddress)
		if opts.Token != "" {
			request.Header.Set("authorization", "Bearer "+opts.Token)
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: http.ProxyURL(proxyURL)}
		} else {
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}}, Proxy: http.ProxyURL(proxyURL)}
		}
	} else {
		if opts.Token != "" {
			request.Header.Set("authorization", "Bearer "+opts.Token)
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		} else {
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}}}
		}
	}

	resp, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// lr := &io.LimitedReader{R: resp.Body, N: 10240}
	// buffer := make([]byte, 10240)
	// n, err := io.ReadFull(lr, buffer)
	// return string(buffer[:n]), err
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	res := string(content)
	return res, nil
}
