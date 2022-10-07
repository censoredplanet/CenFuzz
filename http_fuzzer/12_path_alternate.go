package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type PathAlternate struct{}

func (h *PathAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			pathAlternate := util.GeneratePathAlternatives()
			requestWord = &RequestWord{
				Path:     pathAlternate,
				Hostname: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[pathAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		pathAllAlternate := util.GenerateAllPathAlternatives()
		for _, path := range pathAllAlternate {
			requestWords = append(requestWords, &RequestWord{
				Path:     path,
				Hostname: "%s",
			})
		}
	}
	return requestWords
}

func (g *PathAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
