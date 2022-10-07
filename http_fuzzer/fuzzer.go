package http_fuzzer

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/censoredplanet/CenFuzz/connection"
	"github.com/censoredplanet/CenFuzz/util"
	"github.com/google/go-cmp/cmp"
	tld "github.com/jpillora/go-tld"
)

type RequestWord struct {
	Hostname          string
	GetWord           string `default:"GET"`
	HttpWord          string `default:"HTTP/1.1"`
	HostWord          string `default:"Host:"`
	HttpDelimiterWord string `default:"\r\n"`
	Path              string `default:"/"`
	Header            string `default:""`
}

func containsRequestWord(s []*RequestWord, e *RequestWord) bool {
	for _, a := range s {
		if cmp.Equal(a, e) {
			return true
		}
	}
	return false
}

// Returns of an HTTP request for URL.
func FormatHttpRequest(requestWord RequestWord) string {
	getWord := "GET"
	if requestWord.GetWord != "" {
		getWord = requestWord.GetWord
	}
	httpWord := "HTTP/1.1"
	if requestWord.HttpWord != "" {
		httpWord = requestWord.HttpWord
	}
	hostWord := "Host:"
	if requestWord.HostWord != "" {
		hostWord = requestWord.HostWord
	}
	httpDelimiterWord := "\r\n"
	if requestWord.HttpDelimiterWord != "" {
		httpDelimiterWord = requestWord.HttpDelimiterWord
	}
	path := " / "
	if requestWord.Path != "" {
		path = requestWord.Path
	}
	header := ""
	if requestWord.Header != "" {
		header = requestWord.Header
	}

	//Handle hostname changes - This has to be done at runtime, since the strategies would be selected first, but the hostname itself is only known at runtime
	var host string
	hostNameParts := strings.Split(requestWord.Hostname, "|")
	if len(hostNameParts) > 1 {
		//ServerNameParts[1] contains the strategy to be run at runtime
		if hostNameParts[1] == "omit" {
			format := "%s%s%s%s\r\n%s\r\n"
			return fmt.Sprintf(format, getWord, path, httpWord, httpDelimiterWord, header)
		} else if hostNameParts[1] == "empty" {
			host = ""
		} else if hostNameParts[1] == "repeat" {
			//Now there should be a third part that says how many times to repeat
			repeatTimes, err := strconv.Atoi(hostNameParts[2])
			if err != nil {
				log.Println("[https_fuzzer.CreateTLSConfig] Error converting string into integer (repeat)")
				log.Println(err)
				log.Println("Reverting to default")
				host = hostNameParts[0]
			} else {
				host = util.Repeat(hostNameParts[0], repeatTimes)
			}
		} else if hostNameParts[1] == "reverse" {
			host = util.Reverse(hostNameParts[0])
		} else if hostNameParts[1] == "tld" {
			domainParts, _ := tld.Parse("https://" + hostNameParts[0])
			if domainParts.Subdomain != "" {
				host = domainParts.Subdomain + "." + domainParts.Domain + "." + hostNameParts[2]
			} else {
				host = domainParts.Domain + "." + hostNameParts[2]
			}
		} else if hostNameParts[1] == "subdomain" {
			domainParts, _ := tld.Parse("https://" + hostNameParts[0])
			host = hostNameParts[2] + "." + domainParts.Domain + "." + domainParts.TLD
		}
	} else {
		host = requestWord.Hostname
	}

	format := "%s%s%s%s%s%s\r\n%s\r\n"
	return fmt.Sprintf(format, getWord, path, httpWord, httpDelimiterWord, hostWord, host, header)
}

func MakeConnection(target string, hostname string, requestWord RequestWord) (interface{}, interface{}, interface{}) {
	formattedHostname := FormatHttpRequest(requestWord)
	conn := connection.NewConnection(target, 80)
	if conn == nil {
		return formattedHostname, nil, "Dial"
	}

	response := connection.SendHTTPRequest(conn, formattedHostname)
	if conn.Err != nil {
		return formattedHostname, nil, conn.Err.Error()
	}
	return formattedHostname, response, nil
}

type Fuzzer interface {
	Init(all bool) []*RequestWord
	Fuzz(ip string, domain string, requestWord RequestWord) (interface{}, interface{}, interface{})
}
