package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HttpDelimiterWordRemove struct{}

func (h *HttpDelimiterWordRemove) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			httpDelimiterWord := util.GenerateRandomlyRemovedWord("\r\n")
			requestWord = &RequestWord{
				HttpDelimiterWord: httpDelimiterWord,
				Hostname:          "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HttpDelimiterWordRemove.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		httpDelimiterWordAllRemove := util.GenerateAllSubstringPermutations("\r\n")
		for _, httpDelimiterWord := range httpDelimiterWordAllRemove {
			requestWords = append(requestWords, &RequestWord{
				HttpDelimiterWord: httpDelimiterWord,
				Hostname:          "%s",
			})
		}
	}
	return requestWords
}

func (g *HttpDelimiterWordRemove) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
