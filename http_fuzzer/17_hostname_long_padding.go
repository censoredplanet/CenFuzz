package http_fuzzer

import (
	"log"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type HostnameLongPadding struct{}

func (s *HostnameLongPadding) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			HostnameWithLongPadding := util.GenerateHostNameLongPadding()
			requestWord = &RequestWord{
				Hostname: HostnameWithLongPadding,
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[HostnameWithLongPadding.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		HostnameAllLongPadding := util.GenerateAllHostNameLongPaddings()
		for _, Hostname := range HostnameAllLongPadding {
			requestWords = append(requestWords, &RequestWord{Hostname: Hostname})
		}
	}
	return requestWords
}

func (s *HostnameLongPadding) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
