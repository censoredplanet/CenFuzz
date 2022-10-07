package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HostWordAlternate struct{}

func (h *HostWordAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			hostWordAlternate := util.GenerateHostAlternatives()
			requestWord = &RequestWord{
				HostWord: hostWordAlternate,
				Hostname: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HostWordAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		hostWordAllAlternate := util.GenerateAllHostAlternatives()
		for _, hostWord := range hostWordAllAlternate {
			requestWords = append(requestWords, &RequestWord{
				HostWord: hostWord,
				Hostname: "%s",
			})
		}
	}
	return requestWords
}

func (g *HostWordAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
