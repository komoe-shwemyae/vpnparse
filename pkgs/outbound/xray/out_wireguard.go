package parser

import (
	"net/url"
	"strings"

	"github.com/gvcgo/goutils/pkgs/crypt"
	"github.com/gvcgo/goutils/pkgs/gtui"
)

const (
	SchemeSS        string = "ss://"
	SchemeSSR       string = "ssr://"
	SchemeTrojan    string = "trojan://"
	SchemeVless     string = "vless://"
	SchemeVmess     string = "vmess://"
	SchemeWireguardOld string = "wireguard://"
	SchemeWireguard    string = "wg://"
)

func GetVpnScheme(rawUri string) string {
	sep := "://"
	if !strings.Contains(rawUri, sep) {
		return ""
	}
	sList := strings.Split(rawUri, sep)
	return sList[0] + sep
}

func HandleQuery(rawUri string) (result string) {
	result = rawUri
	if !strings.Contains(rawUri, "?") {
		return
	}
	sList := strings.Split(rawUri, "?")
	query := sList[1]
	if strings.Contains(query, ";") && !strings.Contains(query, "&") {
		result = sList[0] + "?" + strings.ReplaceAll(sList[1], ";", "&")
	}
	return
}

func ParseRawUri(rawUri string) (result string) {
	if strings.HasPrefix(rawUri, SchemeVmess) {
		if r := crypt.DecodeBase64(strings.Split(rawUri, "://")[1]); r != "" {
			result = SchemeVmess + r
		}
		return
	}

	if strings.Contains(rawUri, "\u0026") {
		rawUri = strings.ReplaceAll(rawUri, "\u0026", "&")
	}
	rawUri, _ = url.QueryUnescape(rawUri)
	_, err := url.Parse(rawUri)
	result = rawUri
	if err != nil {
		gtui.PrintError(err)
		return
	}

	
	if strings.Contains(result, "%") {
		result, _ = url.QueryUnescape(result)
	}
	result = HandleQuery(result)
	return
}






