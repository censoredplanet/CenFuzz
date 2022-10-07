package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HttpWordRemove struct{}

func (h *HttpWordRemove) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			httpWordRemove := util.GenerateRandomlyRemovedWord("HTTP/1.1")
			requestWord = &RequestWord{
				HttpWord: httpWordRemove,
				Hostname: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HttpWordRemove.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		httpWordAllRemove := util.GenerateAllSubstringPermutations("HTTP/1.1")
		for _, httpWord := range httpWordAllRemove {
			requestWords = append(requestWords, &RequestWord{
				HttpWord: httpWord,
				Hostname: "%s",
			})
		}
	}
	return requestWords
}

func (h *HttpWordRemove) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
