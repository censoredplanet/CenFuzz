package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HttpWordCapitalize struct{}

func (h *HttpWordCapitalize) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			httpWordCapitalize := util.GenerateRandomCapitalizedValues("HTTP/1.1")
			requestWord = &RequestWord{
				HttpWord: httpWordCapitalize,
				Hostname: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HttpWordCapitalize.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		httpWordAllCapitalize := util.GenerateAllCapitalizedPermutations("HTTP/1.1")
		for _, httpWord := range httpWordAllCapitalize {
			requestWords = append(requestWords, &RequestWord{
				HttpWord: httpWord,
				Hostname: "%s",
			})
		}
	}
	return requestWords
}

func (h *HttpWordCapitalize) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
