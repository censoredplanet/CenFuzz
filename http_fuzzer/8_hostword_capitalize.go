package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HostWordCapitalize struct{}

func (h *HostWordCapitalize) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			hostWordCapitalize := util.GenerateRandomCapitalizedValues("Host: ")
			requestWord = &RequestWord{
				HostWord: hostWordCapitalize,
				Hostname: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HostWordCapitalize.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		hostWordAllRemove := util.GenerateAllCapitalizedPermutations("Host: ")
		for _, hostWord := range hostWordAllRemove {
			requestWords = append(requestWords, &RequestWord{
				HostWord: hostWord,
				Hostname: "%s",
			})
		}
	}
	return requestWords
}

func (h *HostWordCapitalize) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
