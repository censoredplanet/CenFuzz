package worker

import (
	"regexp"
	"strings"
	"sync"

	"github.com/censoredplanet/CenFuzz/util"
)

type FuzzerSpec int64

func (f FuzzerSpec) Fuzzer() int {
	return int(f)
}
func Break(err interface{}) bool {
	if err == "Dial" {
		return true
	}
	return false
}

// Returns version of domain starting with label "www"
func WwwDomainVersion(domain string) string {
	if strings.HasPrefix(domain, "www.") {
		return domain
	} else {
		return "www." + domain
	}
}

// Returns version of domain with the starting label "www"
func NonWwwDomainVersion(domain string) string {
	if strings.HasPrefix(domain, "www.") {
		return domain[len("www."):]
	} else {
		return domain
	}
}

// Markers for replacing occurences of the request domain, timestamps, and
// ids in responses when generating templates. The motivation for replacing
// predictable variable response elements with a marker instead of deleting them
// is to allow the frequency of occurances to be counted.
//
// Because the marker contains a random string it is unlikely actual response
// content will be confused with it.
const ReplacementMarkerSuffix = "-FUZZER-6B6LwyGe4cHLccMAfNYVbQ]"
const DomainReplacmentMarker = "[DOMAIN" + ReplacementMarkerSuffix
const TimestampReplacmentMarker = "[TIMESTAMP" + ReplacementMarkerSuffix
const AkamiIdReplacementMarker = "[AKAMAI_ID" + ReplacementMarkerSuffix

const timestampFormat = "[0-2][0-9]:[0-9][0-9]:[0-9][0-9]"

var timestampRegex = regexp.MustCompile(timestampFormat)

// I could not find a published list of Akami's IP address ranges. To identify
// vantage points which belong to Akami we can search for the AkamaiGHost
// Reference id.
var akamaiRegex = regexp.MustCompile("Reference&#32;&#35[^\n]*\n")

// Returns a function which replaces www and non-www forms a domain with a
// marker.
func newDomainFilter(domain string) func(string) string {
	wwwDomainFmt := "(?i)" + regexp.QuoteMeta(WwwDomainVersion(domain))
	domainFmt := "(?i)" + regexp.QuoteMeta(NonWwwDomainVersion(domain))
	wwwDomainRegex := regexp.MustCompile(wwwDomainFmt)
	domainRegex := regexp.MustCompile(domainFmt)
	return func(text string) string {
		// Because the non-www version of a domain is a suffix of the www
		// version, the www version must be replaced first. Otherwise the "www."
		// would remain.
		r := wwwDomainRegex.ReplaceAllString(text, DomainReplacmentMarker)
		return domainRegex.ReplaceAllString(r, DomainReplacmentMarker)
	}
}

type Worker interface {
	FuzzerObjects(fuzzerList []*util.FuzzerInput) interface{}
	Work(ip string, domain string, requestWord interface{}) interface{}
	GenerateTemplate(response interface{}, keyword string) interface{}
	MatchesControl(results []*util.Result) []*util.Result
	SendResults(results []*util.Result, ResultsQueue chan<- *util.Result)
	Worker(workQueue <-chan interface{}, resultQueue chan<- *util.Result, uncensoredDomain string, wg *sync.WaitGroup, done chan<- bool)
}
