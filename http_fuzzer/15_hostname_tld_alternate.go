package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HostnameTLDAlternate struct{}

func (h *HostnameTLDAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			HostnameAlternate := util.GenerateTLDAlternatives()
			requestWord = &RequestWord{
				Hostname: HostnameAlternate,
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HostnameTLDAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		HostnameAllAlternatives := util.GenerateAllTLDAlternatives()
		for _, Hostname := range HostnameAllAlternatives {
			requestWords = append(requestWords, &RequestWord{Hostname: Hostname})
		}
	}
	return requestWords
}

func (h *HostnameTLDAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
