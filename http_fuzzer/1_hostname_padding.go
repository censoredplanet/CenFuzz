package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HostnamePadding struct{}

func (h *HostnamePadding) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			HostnameWithRandomPadding := util.GenerateHostNameRandomPadding()
			requestWord = &RequestWord{
				Hostname: HostnameWithRandomPadding,
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HostnameWithRandomPadding.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		hostnameAllPadding := util.GenerateAllHostNamePaddings()
		for _, hostname := range hostnameAllPadding {
			requestWords = append(requestWords, &RequestWord{Hostname: hostname})
		}
	}
	return requestWords
}

func (h *HostnamePadding) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
