package https_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type ServernameLongPadding struct{}

func (s *ServernameLongPadding) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			ServerNameWithLongPadding := util.GenerateHostNameLongPadding()
			requestWord = &RequestWord{
				Servername: ServerNameWithLongPadding,
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[ServerNameWithLongPadding.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		servernameAllLongPadding := util.GenerateAllHostNameLongPaddings()
		for _, servername := range servernameAllLongPadding {
			requestWords = append(requestWords, &RequestWord{Servername: servername})
		}
	}
	return requestWords
}

func (s *ServernameLongPadding) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
