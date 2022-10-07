package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type GetWordRemove struct{}

func (g *GetWordRemove) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			getWordRemove := util.GenerateRandomlyRemovedWord("GET")
			requestWord = &RequestWord{
				GetWord:  getWordRemove,
				Hostname: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[GetWordRemove.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		getWordAllRemove := util.GenerateAllSubstringPermutations("GET")
		for _, getWord := range getWordAllRemove {
			requestWords = append(requestWords, &RequestWord{
				GetWord:  getWord,
				Hostname: "%s",
			})
		}
	}
	return requestWords
}

func (g *GetWordRemove) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
