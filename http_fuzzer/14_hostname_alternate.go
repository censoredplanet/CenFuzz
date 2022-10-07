package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HostNameAlternate struct{}

func (h *HostNameAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			hostNameAlternate := util.GenerateHostNameAlternatives()
			requestWord = &RequestWord{
				Hostname: hostNameAlternate,
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HostNameAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		hostnameAllAlternatives := util.GenerateAllHostNameAlternatives()
		for _, hostname := range hostnameAllAlternatives {
			requestWords = append(requestWords, &RequestWord{Hostname: hostname})
		}
	}
	return requestWords
}

func (h *HostNameAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
