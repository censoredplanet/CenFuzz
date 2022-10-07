package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type GetWordCapitalize struct{}

func (g *GetWordCapitalize) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			getWordCapitalize := util.GenerateRandomCapitalizedValues("GET")
			requestWord = &RequestWord{
				GetWord:  getWordCapitalize,
				Hostname: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[GetWordCapitalize.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		getWordsAllCapitalize := util.GenerateAllCapitalizedPermutations("GET")
		for _, getWord := range getWordsAllCapitalize {
			requestWords = append(requestWords, &RequestWord{
				GetWord:  getWord,
				Hostname: "%s",
			})
		}
	}
	return requestWords
}

func (g *GetWordCapitalize) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
