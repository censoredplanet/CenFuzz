package https_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type ServernamePadding struct{}

func (s *ServernamePadding) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			ServerNameWithRandomPadding := util.GenerateHostNameRandomPadding()
			requestWord = &RequestWord{
				Servername: ServerNameWithRandomPadding,
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[ServerNameWithRandomPadding.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		servernameAllPadding := util.GenerateAllHostNamePaddings()
		for _, servername := range servernameAllPadding {
			requestWords = append(requestWords, &RequestWord{Servername: servername})
		}
	}
	return requestWords
}

func (s *ServernamePadding) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
