package https_fuzzer

import (
	"log"
	"strconv"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type MinVersionAlternate struct{}

func (m *MinVersionAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			minVersion := util.GenerateVersionAlternatives()
			minVersionInt, err := strconv.ParseUint(minVersion, 10, 16)
			if err != nil {
				log.Println("[MinVersionAlternate.Init] Could not convert string to int")
				log.Println(err)
				continue
			}
			requestWord = &RequestWord{
				MinVersion: uint16(minVersionInt),
				Servername: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[MinVersionAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		allMinVersions := util.GenerateAllVersionAlternatives()
		for _, minVersion := range allMinVersions {
			minVersionInt, err := strconv.ParseUint(minVersion, 10, 16)
			if err != nil {
				log.Println("[MinVersionAlternate.Init] Could not convert string to int")
				log.Println(err)
				continue
			}
			requestWords = append(requestWords, &RequestWord{MinVersion: uint16(minVersionInt), Servername: "%s"})
		}
	}
	return requestWords
}

func (m *MinVersionAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
