package util

import (
	"bytes"
	rand2 "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"time"

	combinations "github.com/mxschmitt/golang-combinations"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())

}

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func Repeat(s string, n int) string {
	returnString := ""
	for i := 0; i < n; i++ {
		returnString += s
	}
	return returnString
}

func GenerateRandomCapitalizedValues(word string) string {
	randomlyCapitalizedWord := ""
	for _, char := range word {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') {
			randomlyCapitalizedWord += string(char)
			continue
		}
		rand.Seed(time.Now().UTC().UnixNano())
		choice := rand.Intn(2)
		if choice == 0 {
			randomlyCapitalizedWord += strings.ToLower(string(char))
		} else if choice == 1 {
			randomlyCapitalizedWord += strings.ToUpper(string(char))
		}
	}
	return randomlyCapitalizedWord
}

func unique(stringSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range stringSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func CapitalizedPermutations(ip string, op string) []string {
	var s []string
	if len(ip) == 0 {
		return []string{op}
	}
	lowerChar := strings.ToLower(string(ip[0]))
	upperChar := strings.ToUpper(string(ip[0]))
	ip = ip[1:len(ip)]
	s = append(s, CapitalizedPermutations(ip, op+lowerChar)...)
	s = append(s, CapitalizedPermutations(ip, op+upperChar)...)
	return unique(s)
}

//TODO: This currently only works for ASCII characters
func GenerateAllCapitalizedPermutations(word string) []string {
	return CapitalizedPermutations(word, "")
}

func GenerateRandomlyRemovedWord(word string) string {
	randomlyRemovedWord := ""
	for _, char := range word {
		rand.Seed(time.Now().UTC().UnixNano())
		choice := rand.Intn(2)
		if choice == 1 {
			randomlyRemovedWord += string(char)
		}
	}
	return randomlyRemovedWord
}

func GenerateAllSubstringPermutations(word string) []string {
	splitWord := strings.Split(word, "")
	combs := combinations.All(splitWord)
	var permutations []string
	for _, elem := range combs {
		permutations = append(permutations, strings.Join(elem, ""))
	}
	return permutations
}

func GenerateAlternatives(alternatives []string) string {
	rand.Seed(time.Now().UTC().UnixNano())
	choice := rand.Intn(len(alternatives))
	return alternatives[choice]
}

func GenerateAllAlternatives(alternatives []string) []string {
	return alternatives
}

func GenerateHostNameRandomPadding() string {
	prefixPaddingLength := rand.Intn(5)
	suffixPaddingLength := rand.Intn(5)
	hostnameWithPadding := strings.Repeat("*", prefixPaddingLength)
	hostnameWithPadding += "%s"
	hostnameWithPadding += strings.Repeat("*", suffixPaddingLength)
	return hostnameWithPadding
}
func GenerateAllHostNamePaddings() []string {
	var hostnameWithAllPadding []string
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			hostnameWithPadding := strings.Repeat("*", i)
			hostnameWithPadding += "%s"
			hostnameWithPadding += strings.Repeat("*", j)
			hostnameWithAllPadding = append(hostnameWithAllPadding, hostnameWithPadding)
		}

	}
	return hostnameWithAllPadding
}

var GetAlternatives = []string{"POST", "PUT", "PATCH", "DELETE", "XXX", " "}

func GenerateGetAlternatives() string {
	return GenerateAlternatives(GetAlternatives)
}

func GenerateAllGetAlternatives() []string {
	return GenerateAllAlternatives(GetAlternatives)
}

var HttpAlternatives = []string{"XXXX/1.1", "HTTP/11.1", "HTTP/1.12", "/11.1", "HTTP2", "HTTP3", "HTTP9", "HTTP/2", "HTTP/3", "HTTP/9", " ", "HTTPx/1.1", "HTTP /1.1", "HTTP/ 1.1", "HTTP/1.1x", "HTTP/x1.1"}

func GenerateHttpAlternatives() string {
	return GenerateAlternatives(HttpAlternatives)
}

func GenerateAllHttpAlternatives() []string {
	return GenerateAllAlternatives(HttpAlternatives)
}

var HostAlternatives = []string{"XXXX: ", "XXXX:", "Host:\r\n", "Hostwww.", "Host:www.", "HostHeader:", " "}

func GenerateHostAlternatives() string {
	return GenerateAlternatives(HostAlternatives)
}

func GenerateAllHostAlternatives() []string {
	return GenerateAllAlternatives(HostAlternatives)
}

var PathAlternatives = []string{"/ ", " z ", " ? ", " ", " /", "**", " /x", "x/ "}

func GeneratePathAlternatives() string {
	return GenerateAlternatives(PathAlternatives)
}

func GenerateAllPathAlternatives() []string {
	return GenerateAllAlternatives(PathAlternatives)
}

var HTTPHeaders = []string{"Accept: text/html", "Accept: application/xml", "Accept: text/html,application/xhtml+xml", "Accept: application/json", "Accept: xxx", "Accept-Charset: utf-8", "Accept-Charset: xxx", "Accept-Datetime: Thu, 31 May 2007 20:35:00 GMT", "Accept-Datetime: xxx", "Accept-Encoding: gzip, deflate", "Accept-Encoding: xxx", "Accept-Language: en-US", "Accept-Language: xxx", "Access-Control-Request-Method: GET", "Access-Control-Request-Method: xxx", "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "Cache-Control: no-cache", "Cache-Control: xxx", "Connection: keep-alive", "Connection: xxx", "Content-Encoding: gzip", "Content-Encoding: xxx", "Content-Length: 1000", "Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==", "Content-Type: application/x-www-form-urlencoded", "Content-Type: xxx", "Cookie: $Version=1; Skin=new;", "Cookie: xxx", "Date: Tue, 15 Nov 1994 08:12:31 GMT", "Expect: 100-continue", "Expect: xxx", "From: user@example.com", "If-Match: \"737060cd8c284d8af7ad3082f209582d\"", "If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT", "If-None-Match: \"737060cd8c284d8af7ad3082f209582d]\"", "If-Range: \"737060cd8c284d8af7ad3082f209582d\"", "If-Unmodified-Since: Sat, 29 Oct 1994 19:43:31 GMT", "Max-Forwards: 10", "Max-Forwards: xxx", "Origin: http://www.example-xxx.com", "Pragma: no-cache", "Pragma: xxx", "Prefer: return=representation", "Prefer: xxx", "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "Range: bytes=500-999", "Referer: http://example-xxx.com", "TE: trailers, deflate", "Trailer: Max-Forwards", "Trailer: xxx", "Transfer-Encoding: chunked", "Transfer-Encoding: xxx", "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:12.0) Gecko/20100101 Firefox/12.0", "User-Agent: xxx", "Upgrade: h2c, HTTPS/1.3, IRC/6.9, RTA/x11, websocket", "Upgrade: xxx", "Via: 1.0 fred, 1.1 example-xxx.com (Apache/1.1)", "Warning: 199 Miscellaneous warning", "Warning: xxx"}

func GenerateHeaderAlternatives() string {
	return GenerateAlternatives(HTTPHeaders)
}

func GenerateAllHeaderAlternatives() []string {
	return GenerateAllAlternatives(HTTPHeaders)
}

var versionAlternatives = []string{fmt.Sprint(tls.VersionTLS10), fmt.Sprint(tls.VersionTLS11), fmt.Sprint(tls.VersionTLS12), fmt.Sprint(tls.VersionTLS13)}

func GenerateVersionAlternatives() string {
	return GenerateAlternatives(versionAlternatives)
}

func GenerateAllVersionAlternatives() []string {
	return GenerateAllAlternatives(versionAlternatives)
}

var cipherSuiteAlternatives = []string{fmt.Sprint(tls.TLS_RSA_WITH_RC4_128_SHA),
	fmt.Sprint(tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA),
	fmt.Sprint(tls.TLS_RSA_WITH_AES_128_CBC_SHA),
	fmt.Sprint(tls.TLS_RSA_WITH_AES_256_CBC_SHA),
	fmt.Sprint(tls.TLS_RSA_WITH_AES_128_CBC_SHA256),
	fmt.Sprint(tls.TLS_RSA_WITH_AES_128_GCM_SHA256),
	fmt.Sprint(tls.TLS_RSA_WITH_AES_256_GCM_SHA384),
	fmt.Sprint(tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA),
	fmt.Sprint(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
	fmt.Sprint(tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
	fmt.Sprint(tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA),
	fmt.Sprint(tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA),
	fmt.Sprint(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
	fmt.Sprint(tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
	fmt.Sprint(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
	fmt.Sprint(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
	fmt.Sprint(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
	fmt.Sprint(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
	fmt.Sprint(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
	fmt.Sprint(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
	fmt.Sprint(tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
	fmt.Sprint(tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
	fmt.Sprint(tls.TLS_AES_128_GCM_SHA256),
	fmt.Sprint(tls.TLS_AES_256_GCM_SHA384),
	fmt.Sprint(tls.TLS_CHACHA20_POLY1305_SHA256)}

func GenerateCipherSuiteAlternatives() string {
	return GenerateAlternatives(cipherSuiteAlternatives)
}

func GenerateAllCipherSuiteAlternatives() []string {
	return GenerateAllAlternatives(cipherSuiteAlternatives)
}

func GenerateCertificate(commonname string) ([]byte, []byte, error) {

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2022),
		Subject: pkix.Name{
			Organization:  []string{"Internet Measurement"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{"Test 123"},
			PostalCode:    []string{"12345"},
			CommonName:    commonname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err := rsa.GenerateKey(rand2.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand2.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Internet Measurement"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{"Test 123"},
			PostalCode:    []string{"12345"},
			CommonName:    commonname,
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand2.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand2.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return certPEM.Bytes(), certPrivKeyPEM.Bytes(), nil
}

var commonnames = []string{"www.test.com", "XXXX", "www.pornhub.com"}

func GenerateCertificateAlternatives() string {
	return GenerateAlternatives(commonnames)
}

func GenerateAllCertificateAlternatives() []string {
	return GenerateAllAlternatives(commonnames)
}

var servernames = []string{"%s|omit", "%s|empty", "%s|repeat|2", "%s|repeat|3", "%s|reverse"}

func GenerateServerNameAlternatives() string {
	return GenerateAlternatives(servernames)
}

func GenerateAllServerNameAlternatives() []string {
	return GenerateAllAlternatives(servernames)
}

//https://azbigmedia.com/business/here-are-2021s-most-popular-tlds-and-domain-registration-trends/
var TLDs = []string{"%s|tld|com", "%s|tld|xyz", "%s|tld|net", "%s|tld|club", "%s|tld|me", "%s|tld|org", "%s|tld|co", "%s|tld|shop", "%s|tld|info", "%s|tld|live"}

func GenerateTLDAlternatives() string {
	return GenerateAlternatives(TLDs)
}

func GenerateAllTLDAlternatives() []string {
	return GenerateAllAlternatives(TLDs)
}

//https://securitytrails.com/blog/most-popular-subdomains-mx-records#:~:text=As%20you%20can%20see%2C%20the,forums%2C%20wiki%2C%20community).
var Subdomains = []string{"%s|subdomain|www", "%s|subdomain|mail", "%s|subdomain|forum", "%s|subdomain|m", "%s|subdomain|blog", "%s|subdomain|shop", "%s|subdomain|forums", "%s|subdomain|wiki", "%s|subdomain|community", "%s|subdomain|ww1"}

func GenerateSubdomainsAlternatives() string {
	return GenerateAlternatives(Subdomains)
}

func GenerateAllSubdomainsAlternatives() []string {
	return GenerateAllAlternatives(Subdomains)
}

var hostnames = []string{"%s|omit", "%s|empty", "%s|repeat|2", "%s|repeat|3", "%s|reverse"}

func GenerateHostNameAlternatives() string {
	return GenerateAlternatives(servernames)
}

func GenerateAllHostNameAlternatives() []string {
	return GenerateAllAlternatives(servernames)
}
