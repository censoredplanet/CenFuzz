package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HeaderAlternate struct{}

func (h *HeaderAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			headerAlternate := util.GenerateHeaderAlternatives()
			requestWord = &RequestWord{
				Header:   headerAlternate + "\r\n",
				Hostname: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HeaderAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		headerAllAlternate := util.GenerateAllHeaderAlternatives()
		for _, header := range headerAllAlternate {
			requestWords = append(requestWords, &RequestWord{
				Header:   header + "\r\n",
				Hostname: "%s",
			})
		}
	}
	return requestWords
}

func (g *HeaderAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
