package worker

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/censoredplanet/CenFuzz/http_fuzzer"
	"github.com/censoredplanet/CenFuzz/util"
)

type HTTPWorker struct{}

func (f FuzzerSpec) HTTPFuzzerInterface() http_fuzzer.Fuzzer {
	switch f.Fuzzer() {
	case 1:
		return &http_fuzzer.HostnamePadding{}
	case 2:
		return &http_fuzzer.GetWordCapitalize{}
	case 3:
		return &http_fuzzer.GetWordRemove{}
	case 4:
		return &http_fuzzer.GetWordAlternate{}
	case 5:
		return &http_fuzzer.HttpWordCapitalize{}
	case 6:
		return &http_fuzzer.HttpWordRemove{}
	case 7:
		return &http_fuzzer.HttpWordAlternate{}
	case 8:
		return &http_fuzzer.HostWordCapitalize{}
	case 9:
		return &http_fuzzer.HostWordRemove{}
	case 10:
		return &http_fuzzer.HostWordAlternate{}
	case 11:
		return &http_fuzzer.HttpDelimiterWordRemove{}
	case 12:
		return &http_fuzzer.PathAlternate{}
	case 13:
		return &http_fuzzer.HeaderAlternate{}
	case 14:
		return &http_fuzzer.HostNameAlternate{}
	case 15:
		return &http_fuzzer.HostnameTLDAlternate{}
	case 16:
		return &http_fuzzer.HostnameSubdomainsAlternate{}
	case 17:
		return &http_fuzzer.HostnameLongPadding{}
	default:
		panic("unknown fuzzer")
	}
}

func HTTPFuzzerMapping(fuzzer int) string {
	switch fuzzer {
	case 1:
		return "Hostname Padding"
	case 2:
		return "Get Word | Capitalize"
	case 3:
		return "Get Word | Remove"
	case 4:
		return "Get Word | Alternate"
	case 5:
		return "Http Word | Capitalize"
	case 6:
		return "Http Word | Remove"
	case 7:
		return "Http Word | Alternate"
	case 8:
		return "Host Word | Capitalize"
	case 9:
		return "Host Word | Remove"
	case 10:
		return "Host Word | Alternate"
	case 11:
		return "Http Delimiter | Remove"
	case 12:
		return "Path | Alternate"
	case 13:
		return "Header | Alternate"
	case 14:
		return "Hostname Alternate"
	case 15:
		return "Hostname TLD Alternate"
	case 16:
		return "Hostname Subdomain Alternate"
	case 17:
		return "Hostname Long Padding"
	default:
		return "NA"
	}
}

type HTTPFuzzerObject struct {
	TestName     string
	Spec         FuzzerSpec
	RequestWords []*http_fuzzer.RequestWord
}

// Using a separate struct to assign work instead of just the input,
// since in the future we may want to assign different work for each vantage point
type HTTPWork struct {
	IP      string
	Domain  string
	Fuzzers []*HTTPFuzzerObject
}

func (h *HTTPWorker) Work(ip string, domain string, fuzzers interface{}) interface{} {
	return &HTTPWork{
		IP:      ip,
		Domain:  domain,
		Fuzzers: fuzzers.([]*HTTPFuzzerObject),
	}
}

func (h *HTTPWorker) FuzzerObjects(fuzzerList []*util.FuzzerInput) interface{} {
	var fuzzerObjects []*HTTPFuzzerObject
	for _, fuzzerStruct := range fuzzerList {

		fuzzerspec := FuzzerSpec(fuzzerStruct.FuzzerNumber)
		fuzzerName := HTTPFuzzerMapping(fuzzerStruct.FuzzerNumber)
		if fuzzerName == "NA" {
			log.Println("[HTTPWorker.FuzzerObjects] WARNING: Fuzzer not available: ", fuzzerStruct.FuzzerNumber)
			continue
		}
		requestWords := fuzzerspec.HTTPFuzzerInterface().Init(fuzzerStruct.All)

		fuzzerObjects = append(fuzzerObjects, &HTTPFuzzerObject{
			TestName:     fuzzerName,
			Spec:         fuzzerspec,
			RequestWords: requestWords,
		})
	}
	return fuzzerObjects

}

func (h *HTTPWorker) GenerateTemplate(response interface{}, keyword string) interface{} {
	if response == nil {
		return nil
	}
	filterDomain := newDomainFilter(keyword)
	filterBody := func(body string) string {
		body = timestampRegex.ReplaceAllString(body, TimestampReplacmentMarker)
		body = akamaiRegex.ReplaceAllString(body, AkamiIdReplacementMarker)
		return filterDomain(body)
	}

	return filterBody(response.(string))
}

// TODO: there are more efficient ways of doing this than going through the list twice, but this will do for now
func (h *HTTPWorker) MatchesControl(results []*util.Result) []*util.Result {
	var normalResponse interface{}
	var normalError interface{}

	for _, result := range results {
		if result.IsNormal == true {
			normalResponse = h.GenerateTemplate(result.Response, result.Domain)
			normalError = result.Error
		}
	}
	for _, result := range results {
		normalDifferences := ""
		uncensoredDifferences := ""
		resultResponseTemplate := h.GenerateTemplate(result.Response, result.Domain)
		uncensoredResponseTemplate := h.GenerateTemplate(result.UncensoredResponse, result.Domain)
		if resultResponseTemplate == normalResponse && result.Error == normalError {
			result.MatchesNormal = true
		} else {
			if resultResponseTemplate == nil && normalResponse != nil {
				normalDifferences += "No expected response;"
			}
			if result.Error == nil && normalError != nil {
				normalDifferences += "No expected error;"
			}
			if normalResponse != nil && (resultResponseTemplate != normalResponse) {
				normalDifferences += "Different response;"
			}
			if normalError != nil && (result.Error != normalError) {
				normalDifferences += "Different error;"
			}
			result.MatchesNormal = false
			result.NormalDifferences = normalDifferences
		}

		if resultResponseTemplate == uncensoredResponseTemplate && result.Error == result.UncensoredError {
			result.MatchesUncensored = true
		} else {
			if resultResponseTemplate == nil && uncensoredResponseTemplate != nil {
				uncensoredDifferences += "No expected response;"
			}
			if result.Error == nil && result.UncensoredError != nil {
				uncensoredDifferences += "No expected error;"
			}
			if uncensoredResponseTemplate != nil && (resultResponseTemplate != uncensoredResponseTemplate) {
				uncensoredDifferences += "Different response;"
			}
			if result.UncensoredError != nil && (result.Error != result.UncensoredError) {
				uncensoredDifferences += "Different error;"
			}
			result.MatchesUncensored = false
			result.UncensoredDifferences = uncensoredDifferences
		}

	}
	return results
}

func (h *HTTPWorker) SendResults(results []*util.Result, ResultsQueue chan<- *util.Result) {
	annotatedResults := h.MatchesControl(results)
	for _, result := range annotatedResults {
		ResultsQueue <- result
	}

}

func (h *HTTPWorker) Worker(workQueue <-chan interface{}, resultQueue chan<- *util.Result, uncensoredDomain string, wg *sync.WaitGroup, done chan<- bool) {
	for w := range workQueue {
		work := w.(*HTTPWork)
		var results []*util.Result

		//Uncensored Normal
		startTime := time.Now()
		uncensoredRequest, uncensoredResponse, uncensoredError := http_fuzzer.MakeConnection(work.IP, uncensoredDomain, http_fuzzer.RequestWord{Hostname: uncensoredDomain})
		time.Sleep(util.Sleep(uncensoredError))
		//Censored Normal
		censoredRequest, censoredResponse, censoredError := http_fuzzer.MakeConnection(work.IP, work.Domain, http_fuzzer.RequestWord{Hostname: work.Domain})
		time.Sleep(util.Sleep(censoredError))
		//We're including the sleep time in endtime because that's the whole time taken for this one measurement. Could do it the other way also.
		endTime := time.Now()
		//Add normal results
		results = append(results, &util.Result{
			IP:                 work.IP,
			Domain:             work.Domain,
			TestName:           "Normal",
			IsNormal:           true,
			Request:            censoredRequest,
			Response:           censoredResponse,
			Error:              censoredError,
			UncensoredRequest:  uncensoredRequest,
			UncensoredResponse: uncensoredResponse,
			UncensoredError:    uncensoredError,
			StartTime:          startTime,
			EndTime:            endTime,
		})

		if Break(censoredError) && Break(uncensoredError) {
			h.SendResults(results, resultQueue)
			wg.Done()
			continue
		}
		var breakFlag bool
		for _, fuzzerObject := range work.Fuzzers {
			breakFlag = false
			for _, requestWord := range fuzzerObject.RequestWords {
				//Uncensored Test
				//Create copy
				uncensoredRequestWord := requestWord.Hostname
				censoredRequestWord := requestWord.Hostname
				formattedUncensoredDomain := fmt.Sprintf(uncensoredRequestWord, uncensoredDomain)
				startTime = time.Now()
				uncensoredRequest, uncensoredResponse, uncensoredErr := fuzzerObject.Spec.HTTPFuzzerInterface().Fuzz(work.IP, work.Domain, http_fuzzer.RequestWord{
					Hostname:          formattedUncensoredDomain,
					GetWord:           requestWord.GetWord,
					HttpWord:          requestWord.HttpWord,
					HostWord:          requestWord.HostWord,
					HttpDelimiterWord: requestWord.HttpDelimiterWord,
					Path:              requestWord.Path,
					Header:            requestWord.Header,
				})
				time.Sleep(util.Sleep(uncensoredErr))
				formattedCensoredDomain := fmt.Sprintf(censoredRequestWord, work.Domain)
				censoredRequest, censoredResponse, censoredErr := fuzzerObject.Spec.HTTPFuzzerInterface().Fuzz(work.IP, work.Domain, http_fuzzer.RequestWord{
					Hostname:          formattedCensoredDomain,
					GetWord:           requestWord.GetWord,
					HttpWord:          requestWord.HttpWord,
					HostWord:          requestWord.HostWord,
					HttpDelimiterWord: requestWord.HttpDelimiterWord,
					Path:              requestWord.Path,
					Header:            requestWord.Header,
				})
				time.Sleep(util.Sleep(censoredErr))
				endTime = time.Now()
				results = append(results, &util.Result{
					IP:                 work.IP,
					Domain:             work.Domain,
					TestName:           fuzzerObject.TestName,
					IsNormal:           false,
					Request:            censoredRequest,
					Response:           censoredResponse,
					Error:              censoredErr,
					UncensoredRequest:  uncensoredRequest,
					UncensoredResponse: uncensoredResponse,
					UncensoredError:    uncensoredErr,
					StartTime:          startTime,
					EndTime:            endTime,
				})
				if Break(censoredError) && Break(uncensoredError) {
					breakFlag = true
					break
				}
			}
			if breakFlag {
				break
			}
		}
		h.SendResults(results, resultQueue)
		wg.Done()
	}
	done <- true

}
