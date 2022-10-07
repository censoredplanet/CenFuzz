package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type GetWordAlternate struct{}

func (g *GetWordAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			getWordAlternate := util.GenerateGetAlternatives()
			requestWord = &RequestWord{
				GetWord:  getWordAlternate,
				Hostname: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[GetWordAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		getWordAllAlternate := util.GenerateAllGetAlternatives()
		for _, getWord := range getWordAllAlternate {
			requestWords = append(requestWords, &RequestWord{
				GetWord:  getWord,
				Hostname: "%s",
			})
		}
	}
	return requestWords
}

func (g *GetWordAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
