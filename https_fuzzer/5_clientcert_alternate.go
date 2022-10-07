package https_fuzzer

import (
	"log"

	utls "github.com/refraction-networking/utls"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type ClientCertAlternate struct{}

func (c *ClientCertAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			certificateServername := util.GenerateCertificateAlternatives()
			clientCertPEM, ClientCertKey, err := util.GenerateCertificate(certificateServername)
			if err != nil {
				log.Println("[ClientCertAlternate.Init] Could not generate client certificate")
				log.Println(err)
				continue
			}
			clientCert, err := utls.X509KeyPair(clientCertPEM, ClientCertKey)
			if err != nil {
				log.Println("[ClientCertAlternate.Init] Could not generate client certificate")
				log.Println(err)
				continue
			}
			requestWord = &RequestWord{
				Certificate: []utls.Certificate{clientCert},
				Servername:  "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[ClientCertAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		allClientCerts := util.GenerateAllCertificateAlternatives()
		for _, clientCert := range allClientCerts {
			clientCertPEM, ClientCertKey, err := util.GenerateCertificate(clientCert)
			if err != nil {
				log.Println("[ClientCertAlternate.Init] Could not generate client certificate")
				log.Println(err)
				continue
			}
			clientCert, err := utls.X509KeyPair(clientCertPEM, ClientCertKey)
			if err != nil {
				log.Println("[ClientCertAlternate.Init] Could not generate client certificate")
				log.Println(err)
				continue
			}
			requestWords = append(requestWords, &RequestWord{Certificate: []utls.Certificate{clientCert}, Servername: "%s"})

		}
	}
	return requestWords
}

func (c *ClientCertAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
