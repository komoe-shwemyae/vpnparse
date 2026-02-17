package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/gvcgo/goutils/pkgs/gtui"
)

type ParserWirguard struct {
	PrivateKey   string `koanf,json:"private_key"`
	PublicKey    string `koanf,json:"public_key"`
	PresharedKey string
	AddrV4       string   `koanf,json:"addr_v4"`
	AddrV6       string   `koanf,json:"addr_v6"`
	DNS          string   `koanf,json:"dns"`
	AllowedIPs   []string `koanf,json:"allowed_ips"`
	Endpoint     string   `koanf,json:"endpoint"`
	ClientID     string   `koanf,json:"client_id"`
	MTU          int      `koanf,json:"mtu"`
	KeepAlive    int
	UDP          bool
	Reserved     []int  `koanf,json:"reserved"`
	Address      string `koanf,json:"address"`
	Port         int    `koanf,json:"port"`
	DeviceName   string `koanf,json:"device_name"`

	*StreamField
}

// Parse detects which style the URI is and parses it accordingly
func (that *ParserWirguard) Parse(rawUri string) error {

	rawUri = strings.TrimSpace(rawUri)

	// remove both possible schemes
	rawUri = strings.TrimPrefix(rawUri, "wireguard://")
	rawUri = strings.TrimPrefix(rawUri, "wg://")

	// ✅ If JSON style (starts with { )
	if strings.HasPrefix(rawUri, "{") {
		if err := json.Unmarshal([]byte(rawUri), that); err != nil {
			gtui.PrintError(err)
			return err
		}
		return nil
	}

	// ✅ Otherwise treat as query style
	u, err := url.Parse("wg://" + rawUri)
	if err != nil {
		gtui.PrintError(err)
		return err
	}

	that.Address = u.Hostname()

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return fmt.Errorf("invalid port")
	}
	that.Port = port

	q := u.Query()

	ep := q.Get("endpoint")
	if ep != "" {
		that.Endpoint = ep
		} else {
	that.Endpoint = fmt.Sprintf("%s:%d", that.Address, that.Port)
}

	// 🔥 restore + in base64 keys
	that.PrivateKey = restorePlus(q.Get("privateKey"))
	that.PublicKey = restorePlus(q.Get("publicKey"))
	that.PresharedKey = restorePlus(q.Get("presharedKey"))
	that.MTU, _ = strconv.Atoi(q.Get("mtu"))
	that.KeepAlive, _ = strconv.Atoi(q.Get("keepalive"))
	that.ClientID = q.Get("client_id")
	that.UDP = q.Get("udp") == "1"
	ip := q.Get("ip")
if ip != "" {
	ips := strings.Split(ip, ",")
	for _, v := range ips {
		v = strings.TrimSpace(v)
		if strings.Contains(v, ":") {
			that.AddrV6 = v
		} else {
			that.AddrV4 = v
		}
	}
}
	
	// Reserved array
	res := q.Get("reserved")
	if res != "" {
		that.Reserved = []int{}
		parts := strings.Split(res, ",")
		for _, v := range parts {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			that.Reserved = append(that.Reserved, n)
		}
	}

	that.DeviceName = q.Get("ifp")

	// =========================
	// ✅ StreamField (optional)
	// =========================
	if q.Get("type") != "" ||
		q.Get("security") != "" ||
		q.Get("host") != "" {

		that.StreamField = &StreamField{
			Network:          q.Get("type"),
			StreamSecurity:   q.Get("security"),
			Path:             q.Get("path"),
			Host:             q.Get("host"),
			GRPCServiceName:  q.Get("serviceName"),
			GRPCMultiMode:    q.Get("mode"),
			ServerName:       q.Get("sni"),
			TLSALPN:          q.Get("alpn"),
			Fingerprint:      q.Get("fp"),
			RealityShortId:   q.Get("sid"),
			RealitySpiderX:   q.Get("spx"),
			RealityPublicKey: q.Get("pbk"),
			PacketEncoding:   q.Get("packetEncoding"),
			TCPHeaderType:    q.Get("headerType"),
		}
	}

	return nil
}

func (that *ParserWirguard) GetAddressList() []string {
	var result []string

	if that.AddrV4 != "" {
		result = append(result, that.AddrV4)
	}
	if that.AddrV6 != "" {
		result = append(result, that.AddrV6)
	}

	return result
}

func restorePlus(s string) string {
	return strings.ReplaceAll(s, " ", "+")
}

func (that *ParserWirguard) GetAddr() string {
	return that.Address
}

func (that *ParserWirguard) GetPort() int {
	return that.Port
}

func (that *ParserWirguard) Show() {
	fmt.Printf("addr: %s, port: %d, privateKey: %s, publicKey: %s\n",
		that.Address,
		that.Port,
		that.PrivateKey,
		that.PublicKey,
	)
}

func TestWireguard() {
	rawUri := `wireguard://{"PrivateKey":"2B8LLjlXkJ608ct0LD0UnuuR9A2GuZUFBMBQJ9GFn1I=","AddrV4":"172.16.0.2","AddrV6":"2606:4700:110:8dad:87b4:b141:584d:e9dc","DNS":"1.1.1.1","MTU":1280,"PublicKey":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","AllowedIPs":["0.0.0.0/0","::/0"],"Endpoint":"198.41.222.233:2087","ClientID":"GpxH","DeviceName":"D9D669","Reserved":null,"Address":"198.41.222.233","Port":2087}`
	p := &ParserWirguard{}
	p.Parse(rawUri)
	p.Show()
}
