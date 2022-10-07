package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HttpWordAlternate struct{}

func (h *HttpWordAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			httpWordAlternate := util.GenerateHttpAlternatives()
			requestWord = &RequestWord{
				HttpWord: httpWordAlternate,
				Hostname: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HttpWordAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		httpWordAllAlternate := util.GenerateAllHttpAlternatives()
		for _, httpWord := range httpWordAllAlternate {
			requestWords = append(requestWords, &RequestWord{
				HttpWord: httpWord,
				Hostname: "%s",
			})
		}
	}
	return requestWords
}

func (g *HttpWordAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
