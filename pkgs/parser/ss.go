package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

var SSMethod map[string]struct{} = map[string]struct{}{
	"2022-blake3-aes-128-gcm":       {},
	"2022-blake3-aes-256-gcm":       {},
	"2022-blake3-chacha20-poly1305": {},
	"none":                          {},
	"aes-128-gcm":                   {},
	"aes-192-gcm":                   {},
	"aes-256-gcm":                   {},
	"chacha20-ietf-poly1305":        {},
	"xchacha20-ietf-poly1305":       {},
	"aes-128-ctr":                   {},
	"aes-192-ctr":                   {},
	"aes-256-ctr":                   {},
	"aes-128-cfb":                   {},
	"aes-192-cfb":                   {},
	"aes-256-cfb":                   {},
	"rc4-md5":                       {},
	"chacha20-ietf":                 {},
	"xchacha20":                     {},
}

/*
shadowsocks: ['plugin', 'obfs', 'obfs-host', 'mode', 'path', 'mux', 'host']
*/

type ParserSS struct {
	Address  string
	Port     int
	Method   string
	Password string

	Host     string
	Mode     string
	Mux      string
	Path     string
	Plugin   string
	OBFS     string
	OBFSHost string

	*StreamField
}

func (that *ParserSS) Parse(rawUri string) {
 // ၁။ Custom handler ကို အရင်ဖြတ်မယ်
 rawUri = that.handleSS(rawUri)
	
 // ၂။ URL တစ်ခုလုံးကို အရင် parse လုပ်ကြည့်မယ်
 u, err := url.Parse(rawUri)
 if err != nil {
  return
 }

 that.StreamField = &StreamField{}
 that.Address = u.Hostname()
	
 portStr := u.Port()
 if portStr != "" {
  that.Port, _ = strconv.Atoi(portStr)
 }

 // ၃။ URL ကနေ Username/Password မထွက်လာရင် Manual String Splitting လုပ်မယ်
 // အကြောင်းရင်းက- Password ထဲမှာ base64 characters (=, /, +) တွေပါရင် 
 // url.Parse က standard မဟုတ်ဘူးဆိုပြီး password ကို empty ပြန်ပေးတတ်လို့ပါ။
	
 userInfoPart := ""
 if strings.Contains(rawUri, "://") && strings.Contains(rawUri, "@") {
  // "ss://abc:123@host" -> "abc:123" အပိုင်းကိုပဲ ယူတာပါ
  temp := strings.Split(rawUri, "://")[1]
  userInfoPart = strings.Split(temp, "@")[0]
 }

 if strings.Contains(userInfoPart, ":") {
  parts := strings.SplitN(userInfoPart, ":", 2)
  that.Method = parts[0]
  // ၄။ ဒီနေရာမှာ base64 decode မလုပ်ဘဲ မူရင်းအတိုင်း တန်းထည့်ပါတယ်
  that.Password = parts[1]
 } else {
  // တကယ်လို့ u.User ကနေ ရနေသေးရင်လည်း ထည့်ပေးထားမယ်
  that.Method = u.User.Username()
  p, _ := u.User.Password()
  if p != "" {
   that.Password = p
  }
 }

 // ၅။ Method မပါလာရင် shadowsocks က error တက်မှာမို့လို့ logic စစ်ပါတယ်
 if that.Method == "rc4" {
  that.Method = "rc4-md5"
 }
	
 // ၆။ အရေးကြီးဆုံးအချက်- password ရော method ရော string အလွတ်မဖြစ်စေရပါဘူး
 // မဟုတ်ရင် V2ray Core က "password is not specified" ဆိုပြီး ငြင်းပါလိမ့်မယ်
 if that.Method == "" {
  that.Method = "aes-256-gcm" // Default method တစ်ခုခု ပေးထားခြင်း
 }

 query := u.Query()
 that.Host = query.Get("host")
 that.Mode = query.Get("mode")
 that.Mux = query.Get("mux")
 that.Path = query.Get("path")
 that.Plugin = query.Get("plugin")
 that.OBFS = query.Get("obfs")
 that.OBFSHost = query.Get("obfs-host")
}

func (that *ParserSS) handleSS(rawUri string) string {
	return strings.ReplaceAll(rawUri, "#ss#\u00261@", "@")
}

func (that *ParserSS) GetAddr() string {
	return that.Address
}

func (that *ParserSS) GetPort() int {
	return that.Port
}

func (that *ParserSS) Show() {
	fmt.Printf("addr: %s, port: %d, method: %s, password: %s\n",
		that.Address,
		that.Port,
		that.Method,
		that.Password)
}

