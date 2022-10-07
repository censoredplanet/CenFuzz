package https_fuzzer

import (
	"log"
	"strconv"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type CipherSuiteAlternate struct{}

func (c *CipherSuiteAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			cipherSuite := util.GenerateCipherSuiteAlternatives()
			cipherSuiteInt, err := strconv.ParseUint(cipherSuite, 10, 16)
			if err != nil {
				log.Println("[CipherSuiteAlternate.Init] Could not convert string to int")
				log.Println(err)
				continue
			}
			requestWord = &RequestWord{
				CipherSuites: []uint16{uint16(cipherSuiteInt)},
				Servername:   "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[CipherSuiteAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		allCipherSuites := util.GenerateAllCipherSuiteAlternatives()
		for _, cipherSuite := range allCipherSuites {
			cipherSuiteInt, err := strconv.ParseUint(cipherSuite, 10, 16)
			if err != nil {
				log.Println("[CipherSuiteAlternate.Init] Could not convert string to int")
				log.Println(err)
				continue
			}
			requestWords = append(requestWords, &RequestWord{CipherSuites: []uint16{uint16(cipherSuiteInt)}, Servername: "%s"})
		}
	}
	return requestWords
}

func (c *CipherSuiteAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
