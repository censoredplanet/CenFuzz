package https_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type ServernameTLDAlternate struct{}

func (s *ServernameTLDAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			ServerNameAlternate := util.GenerateTLDAlternatives()
			requestWord = &RequestWord{
				Servername: ServerNameAlternate,
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[ServernameTLDAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		servernameAllAlternatives := util.GenerateAllTLDAlternatives()
		for _, servername := range servernameAllAlternatives {
			requestWords = append(requestWords, &RequestWord{Servername: servername})
		}
	}
	return requestWords
}

func (s *ServernameTLDAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
