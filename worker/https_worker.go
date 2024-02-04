package worker

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/censoredplanet/CenFuzz/https_fuzzer"
	"github.com/censoredplanet/CenFuzz/util"
	"github.com/google/go-cmp/cmp"
)

func HTTPSFuzzerMapping(fuzzer int) string {
	switch fuzzer {
	case 1:
		return "SNI Padding"
	case 2:
		return "Min Version Alternate"
	case 3:
		return "Max Version Alternate"
	case 4:
		return "CipherSuite Alternate"
	case 5:
		return "Client Certificate Alternate"
	case 6:
		return "SNI Alternate"
	case 7:
		return "SNI TLD Alternate"
	case 8:
		return "SNI Subdomain Alternate"
	case 9:
		return "SNI Long Padding"
	default:
		return "NA"
	}
}

type HTTPSWorker struct{}

func (f FuzzerSpec) HTTPSFuzzerInterface() https_fuzzer.Fuzzer {
	switch f.Fuzzer() {
	case 1:
		return &https_fuzzer.ServernamePadding{}
	case 2:
		return &https_fuzzer.MinVersionAlternate{}
	case 3:
		return &https_fuzzer.MaxversionAlternate{}
	case 4:
		return &https_fuzzer.CipherSuiteAlternate{}
	case 5:
		return &https_fuzzer.ClientCertAlternate{}
	case 6:
		return &https_fuzzer.ServernameAlternate{}
	case 7:
		return &https_fuzzer.ServernameTLDAlternate{}
	case 8:
		return &https_fuzzer.ServernameSubdomainsAlternate{}
	case 9:
		return &https_fuzzer.ServernameLongPadding{}
	default:
		panic("unknown fuzzer")
	}
}

type HTTPSFuzzerObject struct {
	TestName     string
	Spec         FuzzerSpec
	RequestWords []*https_fuzzer.RequestWord
}

type HTTPSWork struct {
	IP      string
	Domain  string
	Fuzzers []*HTTPSFuzzerObject
}

func (h *HTTPSWorker) Work(ip string, domain string, fuzzers interface{}) interface{} {
	return &HTTPSWork{
		IP:      ip,
		Domain:  domain,
		Fuzzers: fuzzers.([]*HTTPSFuzzerObject),
	}
}

func (h *HTTPSWorker) FuzzerObjects(fuzzerList []*util.FuzzerInput) interface{} {
	var fuzzerObjects []*HTTPSFuzzerObject
	for _, fuzzerStruct := range fuzzerList {

		fuzzerspec := FuzzerSpec(fuzzerStruct.FuzzerNumber)
		fuzzerName := HTTPSFuzzerMapping(fuzzerStruct.FuzzerNumber)
		if fuzzerName == "NA" {
			log.Println("[HTTPSWorker.FuzzerObjects] WARNING: Fuzzer not available: ", fuzzerStruct.FuzzerNumber)
			continue
		}
		requestWords := fuzzerspec.HTTPSFuzzerInterface().Init(fuzzerStruct.All)

		fuzzerObjects = append(fuzzerObjects, &HTTPSFuzzerObject{
			TestName:     fuzzerName,
			Spec:         fuzzerspec,
			RequestWords: requestWords,
		})
	}
	return fuzzerObjects

}

func (h *HTTPSWorker) GenerateTemplate(response interface{}, keyword string) interface{} {
	if response == nil {
		return nil
	}
	tlsResponse := response.(*util.TLSdata)
	filterDomain := newDomainFilter(keyword)
	filterBody := func(body string) string {
		body = timestampRegex.ReplaceAllString(body, TimestampReplacmentMarker)
		body = akamaiRegex.ReplaceAllString(body, AkamiIdReplacementMarker)
		return filterDomain(body)
	}

	returnResponse := tlsResponse
	returnResponse.HTTPResponse = filterBody(tlsResponse.HTTPResponse.(string))
	return returnResponse
}

// TODO: there are more efficient ways of doing this than going through the list twice, but this will do for now
func (h *HTTPSWorker) MatchesControl(results []*util.Result) []*util.Result {
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

		var normalResponseObject *util.TLSdata
		var resultResponseTemplateObject *util.TLSdata
		var uncensoredResponseTemplateObject *util.TLSdata
		if normalResponse != nil {
			normalResponseObject = normalResponse.(*util.TLSdata)
		}
		if resultResponseTemplate != nil {
			resultResponseTemplateObject = resultResponseTemplate.(*util.TLSdata)
		}
		if uncensoredResponseTemplate != nil {
			uncensoredResponseTemplateObject = uncensoredResponseTemplate.(*util.TLSdata)
		}

		if (resultResponseTemplateObject != nil && normalResponseObject != nil) && cmp.Equal(resultResponseTemplateObject, normalResponseObject) && result.Error == normalError {
			result.MatchesNormal = true
		} else {
			if resultResponseTemplateObject == nil {
				normalDifferences += "Empty censored response;"
			}
			if normalResponseObject == nil {
				normalDifferences += "Empty normal response;" //Should never happen, since we error out earlier if we get a dial error in normal query. Keeping this here just for error handling in case of exception
			}
			if resultResponseTemplateObject != nil && normalResponseObject != nil {
				//TODO: Will first if statement here ever happen?
				if resultResponseTemplateObject.Version == 0 && normalResponseObject.Version != 0 {
					normalDifferences += "No expected response;"
				}
				if result.Error == nil && normalError != nil {
					normalDifferences += "No expected error;"
				}
				if normalResponseObject.Version != 0 && (resultResponseTemplateObject.Version != normalResponseObject.Version) {
					normalDifferences += "Different version;"
				}
				if normalResponseObject.CipherSuite != 0 && (resultResponseTemplateObject.CipherSuite != normalResponseObject.CipherSuite) {
					normalDifferences += "Different ciphersuite;"
				}
				if normalResponseObject.PeerCertificates != nil && (string(resultResponseTemplateObject.PeerCertificates) != string(normalResponseObject.PeerCertificates)) {
					normalDifferences += "Different certificate;"
				}
				if normalError != nil && (result.Error != normalError) {
					normalDifferences += "Different error;"
				}
			}
			result.MatchesNormal = false
		}
		result.NormalDifferences = normalDifferences

		if (resultResponseTemplate != nil && resultResponseTemplateObject != nil) && cmp.Equal(resultResponseTemplateObject, uncensoredResponseTemplateObject) && result.Error == result.UncensoredError {
			result.MatchesUncensored = true
		} else {
			if resultResponseTemplateObject == nil {
				uncensoredDifferences += "Empty censored response;"
				result.MatchesUncensored = false
			}
			if uncensoredResponseTemplateObject == nil {
				uncensoredDifferences += "Empty uncensored response;"
				result.MatchesUncensored = false
			}
			if resultResponseTemplateObject != nil && uncensoredResponseTemplateObject != nil {
				if resultResponseTemplateObject.Version == 0 && uncensoredResponseTemplateObject.Version != 0 {
					uncensoredDifferences += "No expected response;"
				}
				if result.Error == nil && result.UncensoredError != nil {
					uncensoredDifferences += "No expected error;"
				}
				if uncensoredResponseTemplateObject.Version != 0 && (resultResponseTemplateObject.Version != uncensoredResponseTemplateObject.Version) {
					uncensoredDifferences += "Different version;"
				}
				if uncensoredResponseTemplateObject.CipherSuite != 0 && (resultResponseTemplateObject.CipherSuite != uncensoredResponseTemplateObject.CipherSuite) {
					uncensoredDifferences += "Different ciphersuite;"
				}
				if uncensoredResponseTemplateObject.PeerCertificates != nil && (string(resultResponseTemplateObject.PeerCertificates) != string(uncensoredResponseTemplateObject.PeerCertificates)) {
					uncensoredDifferences += "Different certificate;"
				}
				if result.UncensoredError != nil && (result.Error != result.UncensoredError) {
					uncensoredDifferences += "Different error;"
				}
			}
			//NOTE: Taking a call here to mark this as false even if censored and uncensored are both empty
			result.MatchesUncensored = false
		}
		result.UncensoredDifferences = uncensoredDifferences
	}
	return results
}

func (h *HTTPSWorker) SendResults(results []*util.Result, ResultsQueue chan<- *util.Result) {
	annotatedResults := h.MatchesControl(results)
	for _, result := range annotatedResults {
		ResultsQueue <- result
	}

}

func (h *HTTPSWorker) Worker(workQueue <-chan interface{}, resultQueue chan<- *util.Result, uncensoredDomain string, wg *sync.WaitGroup, done chan<- bool) {
	for w := range workQueue {
		work := w.(*HTTPSWork)
		var results []*util.Result

		//Uncensored Normal
		startTime := time.Now()
		uncensoredRequest, uncensoredResponse, uncensoredError := https_fuzzer.MakeConnection(work.IP, uncensoredDomain, https_fuzzer.RequestWord{Servername: uncensoredDomain})
		time.Sleep(util.Sleep(uncensoredError))
		//Censored Normal
		censoredRequest, censoredResponse, censoredError := https_fuzzer.MakeConnection(work.IP, work.Domain, https_fuzzer.RequestWord{Servername: work.Domain})
		time.Sleep(util.Sleep(censoredError))
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
				uncensoredRequestWord := requestWord.Servername
				censoredRequestWord := requestWord.Servername
				formattedUncensoredDomain := fmt.Sprintf(uncensoredRequestWord, uncensoredDomain)
				startTime = time.Now()
				uncensoredRequest, uncensoredResponse, uncensoredErr := fuzzerObject.Spec.HTTPSFuzzerInterface().Fuzz(work.IP, work.Domain, https_fuzzer.RequestWord{
					Servername:   formattedUncensoredDomain,
					MinVersion:   requestWord.MinVersion,
					MaxVersion:   requestWord.MaxVersion,
					CipherSuites: requestWord.CipherSuites,
					Certificate:  requestWord.Certificate,
				})
				time.Sleep(util.Sleep(uncensoredErr))
				formattedCensoredDomain := fmt.Sprintf(censoredRequestWord, work.Domain)
				censoredRequest, censoredResponse, censoredErr := fuzzerObject.Spec.HTTPSFuzzerInterface().Fuzz(work.IP, work.Domain, https_fuzzer.RequestWord{
					Servername:   formattedCensoredDomain,
					MinVersion:   requestWord.MinVersion,
					MaxVersion:   requestWord.MaxVersion,
					CipherSuites: requestWord.CipherSuites,
					Certificate:  requestWord.Certificate,
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
