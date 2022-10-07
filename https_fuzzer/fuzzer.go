package https_fuzzer

import (
	"crypto/x509"
	"log"
	"strconv"
	"strings"

	"github.com/censoredplanet/CenFuzz/connection"
	"github.com/censoredplanet/CenFuzz/util"
	"github.com/google/go-cmp/cmp"
	tld "github.com/jpillora/go-tld"
	utls "github.com/refraction-networking/utls"
)

type RequestWord struct {
	Servername   string
	CipherSuites []uint16
	MinVersion   uint16
	MaxVersion   uint16
	Certificate  []utls.Certificate
}

func containsRequestWord(s []*RequestWord, e *RequestWord) bool {
	for _, a := range s {
		if cmp.Equal(a, e) {
			return true
		}
	}
	return false
}

// Returns of an HTTP request for URL.
func CreateTLSConfig(requestWord RequestWord) *utls.Config {

	//Set max version to TLS 1.2 if we want cipher suites to be configurable. TLS 1.3 cipher suites are not configurable
	//https://pkg.go.dev/crypto/tls#Config
	if len(requestWord.CipherSuites) > 0 {
		if requestWord.MaxVersion == 772 || requestWord.MaxVersion == 0 {
			requestWord.MaxVersion = 771
		}
	}

	var cert utls.Certificate
	if len(requestWord.Certificate) > 0 {
		cert = requestWord.Certificate[0]
		c, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Println("[https_fuzzer.CreateTLSConfig] Error parsing certificate")
		}
		if c.Subject.CommonName == "" {
			clientCertPEM, ClientCertKey, err := util.GenerateCertificate(requestWord.Servername)
			if err != nil {
				log.Println("[https_fuzzer.CreateTLSConfig] Could not generate client certificate")
				log.Println(err)
				return &utls.Config{
					ServerName:         requestWord.Servername,
					InsecureSkipVerify: true,
					CipherSuites:       requestWord.CipherSuites,
					MinVersion:         requestWord.MinVersion,
					MaxVersion:         requestWord.MaxVersion,
				}
			}
			cert, err = utls.X509KeyPair(clientCertPEM, ClientCertKey)
			if err != nil {
				log.Println("[https_fuzzer.CreateTLSConfig] Could not generate client certificate")
				log.Println(err)
				return &utls.Config{
					ServerName:         requestWord.Servername,
					InsecureSkipVerify: true,
					CipherSuites:       requestWord.CipherSuites,
					MinVersion:         requestWord.MinVersion,
					MaxVersion:         requestWord.MaxVersion,
				}
			}
		}
	}

	//Handle servername changes - This has to be done at runtime, since the strategies would be selected first, but the servername itself is only known at runtime
	serverNameParts := strings.Split(requestWord.Servername, "|")
	if len(serverNameParts) > 1 {
		//ServerNameParts[1] contains the strategy to be run at runtime
		if serverNameParts[1] == "omit" {
			return &utls.Config{
				InsecureSkipVerify: true,
				CipherSuites:       requestWord.CipherSuites,
				MinVersion:         requestWord.MinVersion,
				MaxVersion:         requestWord.MaxVersion,
				Certificates:       []utls.Certificate{cert},
			}
		} else if serverNameParts[1] == "empty" {
			return &utls.Config{
				ServerName:         "",
				InsecureSkipVerify: true,
				CipherSuites:       requestWord.CipherSuites,
				MinVersion:         requestWord.MinVersion,
				MaxVersion:         requestWord.MaxVersion,
				Certificates:       []utls.Certificate{cert},
			}
		} else if serverNameParts[1] == "repeat" {
			//Now there should be a third part that says how many times to repeat
			repeatTimes, err := strconv.Atoi(serverNameParts[2])
			if err != nil {
				log.Println("[https_fuzzer.CreateTLSConfig] Error converting string into integer (repeat)")
				log.Println(err)
				log.Println("Reverting to default")
				return &utls.Config{
					ServerName:         requestWord.Servername,
					InsecureSkipVerify: true,
					CipherSuites:       requestWord.CipherSuites,
					MinVersion:         requestWord.MinVersion,
					MaxVersion:         requestWord.MaxVersion,
					Certificates:       []utls.Certificate{cert},
				}
			}
			serverName := util.Repeat(serverNameParts[0], repeatTimes)
			return &utls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: true,
				CipherSuites:       requestWord.CipherSuites,
				MinVersion:         requestWord.MinVersion,
				MaxVersion:         requestWord.MaxVersion,
				Certificates:       []utls.Certificate{cert},
			}
		} else if serverNameParts[1] == "reverse" {
			return &utls.Config{
				ServerName:         util.Reverse(serverNameParts[0]),
				InsecureSkipVerify: true,
				CipherSuites:       requestWord.CipherSuites,
				MinVersion:         requestWord.MinVersion,
				MaxVersion:         requestWord.MaxVersion,
				Certificates:       []utls.Certificate{cert},
			}
		} else if serverNameParts[1] == "tld" {
			domainParts, _ := tld.Parse("https://" + serverNameParts[0])
			var serverName string
			if domainParts.Subdomain != "" {
				serverName = domainParts.Subdomain + "." + domainParts.Domain + "." + serverNameParts[2]
			} else {
				serverName = domainParts.Domain + "." + serverNameParts[2]
			}
			return &utls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: true,
				CipherSuites:       requestWord.CipherSuites,
				MinVersion:         requestWord.MinVersion,
				MaxVersion:         requestWord.MaxVersion,
				Certificates:       []utls.Certificate{cert},
			}
		} else if serverNameParts[1] == "subdomain" {
			domainParts, _ := tld.Parse("https://" + serverNameParts[0])
			serverName := serverNameParts[2] + "." + domainParts.Domain + "." + domainParts.TLD
			return &utls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: true,
				CipherSuites:       requestWord.CipherSuites,
				MinVersion:         requestWord.MinVersion,
				MaxVersion:         requestWord.MaxVersion,
				Certificates:       []utls.Certificate{cert},
			}
		}
	}

	return &utls.Config{
		ServerName:         requestWord.Servername,
		InsecureSkipVerify: true,
		CipherSuites:       requestWord.CipherSuites,
		MinVersion:         requestWord.MinVersion,
		MaxVersion:         requestWord.MaxVersion,
		Certificates:       []utls.Certificate{cert},
	}

}

func MakeConnection(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	config := CreateTLSConfig(requestWord)
	//Recrate updated requestword
	request := &RequestWord{
		Servername:   config.ServerName,
		CipherSuites: config.CipherSuites,
		MinVersion:   config.MinVersion,
		MaxVersion:   config.MaxVersion,
		Certificate:  config.Certificates,
	}
	conn := connection.NewConnection(target, 443)
	if conn == nil {
		return request, nil, "Dial"
	}

	response := connection.SendHTTPSRequest(conn, *config)
	if conn.Err != nil {
		return request, nil, conn.Err.Error()
	}
	return request, response, nil
}

type Fuzzer interface {
	Init(all bool) []*RequestWord
	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{}, interface{})
}
