package https_fuzzer

import (
	"log"
	"strconv"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
)

type MaxversionAlternate struct{}

func (m *MaxversionAlternate) Init(all bool) []*RequestWord {
	var requestWords []*RequestWord
	var requestWord *RequestWord
	retries := 0
	if !all {
		for i := 0; i < config.NumberOfProbesPerTest; i++ {
			maxversion := util.GenerateVersionAlternatives()
			maxversionInt, err := strconv.ParseUint(maxversion, 10, 16)
			if err != nil {
				log.Println("[MaxversionAlternate.Init] Could not convert string to int")
				log.Println(err)
				continue
			}
			requestWord = &RequestWord{
				MaxVersion: uint16(maxversionInt),
				Servername: "%s",
			}
			if containsRequestWord(requestWords, requestWord) {
				i--
				retries += 1
				if retries >= 10 {
					log.Println("[MaxversionAlternate.Init] Could not find a new random value after 10 retries. Breaking.")
					break
				}
			} else {
				requestWords = append(requestWords, requestWord)
				retries = 0
			}
		}
	} else {
		allMaxversions := util.GenerateAllVersionAlternatives()
		for _, maxversion := range allMaxversions {
			maxversionInt, err := strconv.ParseUint(maxversion, 10, 16)
			if err != nil {
				log.Println("[MaxversionAlternate.Init] Could not convert string to int")
				log.Println(err)
				continue
			}
			requestWords = append(requestWords, &RequestWord{MaxVersion: uint16(maxversionInt), Servername: "%s"})
		}
	}
	return requestWords
}

func (m *MaxversionAlternate) Fuzz(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	return MakeConnection(target, hostname, requestWord)
}
