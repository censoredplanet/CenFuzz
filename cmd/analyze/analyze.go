package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/banviktor/asnlookup/pkg/database"
	"github.com/censoredplanet/CenFuzz/bigquery_upload"
	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/geolocate"
	"github.com/censoredplanet/CenFuzz/https_fuzzer"
	"github.com/censoredplanet/CenFuzz/util"
)

type Output struct {
	TestID                    string `json:"TestID"`
	MeasurementType           string `json:"MeasurementType"`
	Country                   string `json:"Country"`
	Protocol                  string `json:"Protocol"`
	DstIP                     string `json:"DstIP"`
	DstASN                    uint32 `json:"DstASN"`
	Domain                    string `json:"Domain"`
	TestName                  string `json:"TestName"`
	IsNormal                  bool   `json:"IsNormal"`
	NormalResponseType        string `json:"NormalResponseType"`
	NormalCensored            bool   `json:"NormalCensored"`
	MatchesNormal             bool   `json:"MatchesNormal"`
	MatchesUncensored         bool   `json:"MatchesUncensored"`
	NormalDifferences         string `json:"NormalDifferences"`
	UncensoredDifferences     string `json:"UncensoredDifferences"`
	Request                   string `json:"Request"`
	RequestStrategy           string `json:"RequestStrategy`
	Response                  string `json:"Response"`
	Error                     string `json:"Error"`
	CensorResponseType        string `json:"CensoredResponseType"`
	UncensoredRequest         string `json:"UncensoredRequest"`
	UncensoredRequestStrategy string `json:"UncensoredRequestStrategy`
	UncensoredResponse        string `json:"UncensoredResponse"`
	UncensoredError           string `json:"UncensoredError"`
	UncensoredResponseType    string `json:"UncensoredResponsetype"`
	StartTime                 string `json:"StartTime"`
	EndTime                   string `json:"EndTime"`
}

func split(fuzz_file string) (string, string, string) {
	return strings.Split(fuzz_file, "_")[0], strings.Split(fuzz_file, "_")[1], strings.Split(fuzz_file, "_")[2]
}

func readSignaturePatterns(patternfile string) map[string]*regexp.Regexp {
	infile := util.OpenFileforRead(patternfile)
	scanner := bufio.NewScanner(infile)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	signatureData := make(map[string]*regexp.Regexp)
	for scanner.Scan() {
		var signature map[string]string
		line := scanner.Text()
		if line == "\n" || line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		d := json.NewDecoder(strings.NewReader(line))
		d.UseNumber()
		if err := d.Decode(&signature); err != nil {
			log.Println(line)
			log.Fatal("Could not unmarshal json: " + err.Error())
		}
		pattern := regexp.QuoteMeta(signature["pattern"])
		pattern = strings.ReplaceAll(pattern, "%", ".*")
		signatureData[signature["fingerprint"]] = regexp.MustCompile(pattern)
	}
	return signatureData
}

func comparePatterns(str string, fingerprintOrder []string, fingerprints map[string]*regexp.Regexp) string {
	for _, fingerprint := range fingerprintOrder {
		pattern := fingerprints[fingerprint]
		if pattern.MatchString(str) {
			return fingerprint
		}
	}
	return ""
}

func responsetype(errString string, response string, fingerprintOrder []string, fingerprints map[string]*regexp.Regexp) string {
	stage := "unknown"
	method := "unknown"
	if errString == "" && response == "" {
		return "empty/empty"
	}
	if errString != "" {
		if strings.Contains(errString, "Dial") {
			stage = "dial"
		} else if strings.Contains(errString, "read") {
			stage = "read"
		} else if strings.Contains(errString, "write") {
			stage = "write"
		}

		if strings.Contains(errString, "imeout") {
			method = "timeout"
		} else if strings.Contains(errString, "reset") {
			method = "rst"
		} else if strings.Contains(errString, "tls") {
			method = "tls"
		}
	}
	if response != "" {
		fingerprint := comparePatterns(response, fingerprintOrder, fingerprints)
		if fingerprint != "" {
			stage = "content"
			method = "blockpage:" + fingerprint
		} else {
			stage = "content"
			method = "http"
		}
	}

	return stage + "/" + method
}

func initializeASNDB() (database.Database, error) {
	builder := database.NewBuilder()
	routeviwsFile := util.OpenFileforRead(config.RouteviewsFile)
	scanner := bufio.NewScanner(routeviwsFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		firstASN := strings.Split(parts[2], "_")[0]
		secondASN := strings.Split(firstASN, ",")[0]
		asn, err := strconv.Atoi(secondASN)
		if err != nil {
			log.Fatal(err)
		}
		_, prefix, _ := net.ParseCIDR(parts[0] + "/" + parts[1])
		err = builder.InsertMapping(prefix, uint32(asn))
		if err != nil {
			log.Fatal(err)
		}
	}
	return builder.Build()
}

func Strategy(testname string, protocol string, domain string, request interface{}) (string, string) {
	strategy := ""
	if protocol == "http" {
		httpRequest := request.(string)
		if strings.Contains(testname, "Hostname") {
			return strings.Replace(httpRequest, domain, "DOMAIN", -1), strings.Replace(strings.Replace(httpRequest, "GET / HTTP/1.1\r\nHost:", "", -1), "\r\n\r\n", "", -1)
		} else if strings.Contains(testname, "Get Word") {
			return strings.Replace(httpRequest, domain, "DOMAIN", -1), strings.Replace(strings.Replace(httpRequest, " / HTTP/1.1\r\nHost:"+domain, "", -1), "\r\n\r\n", "", -1)
		} else if strings.Contains(testname, "Http Word") {
			return strings.Replace(httpRequest, domain, "DOMAIN", -1), strings.Replace(strings.Replace(httpRequest, "GET / ", "", -1), "\r\nHost:"+domain+"\r\n\r\n", "", -1)
		} else if strings.Contains(testname, "Host Word") {
			return strings.Replace(httpRequest, domain, "DOMAIN", -1), strings.Replace(strings.Replace(httpRequest, "GET / HTTP/1.1\r\n", "", -1), " "+domain+"\r\n\r\n", "", -1)
		} else if strings.Contains(testname, "Http Delimiter") {
			return strings.Replace(httpRequest, domain, "DOMAIN", -1), strings.Replace(strings.Replace(httpRequest, "GET / HTTP/1.1", "", -1), "Host:"+domain+"\r\n\r\n", "", -1)
		} else if strings.Contains(testname, "Path | Alternate") {
			return strings.Replace(httpRequest, domain, "DOMAIN", -1), strings.Replace(strings.Replace(httpRequest, "GET ", "", -1), " HTTP/1.1\r\nHost:"+domain+"\r\n\r\n", "", -1)
		} else if strings.Contains(testname, "Header | Alternate") {
			return strings.Replace(httpRequest, domain, "DOMAIN", -1), strings.Replace(httpRequest, "GET / HTTP/1.1\r\nHost:"+domain+"\r\n", "", -1)
		}
	} else {
		var httpsRequest https_fuzzer.RequestWord
		requstByte, err := json.Marshal(request)
		if err != nil {
			log.Fatal(err)
		}
		json.Unmarshal(requstByte, &httpsRequest)
		if strings.Contains(testname, "SNI") {
			return strings.Replace(httpsRequest.Servername, domain, "DOMAIN", -1), httpsRequest.Servername
		} else if strings.Contains(testname, "Min Version") {
			return "Min version|" + strconv.Itoa(int(httpsRequest.MinVersion)) + "|" + strings.Replace(httpsRequest.Servername, domain, "DOMAIN", -1), strconv.Itoa(int(httpsRequest.MinVersion))
		} else if strings.Contains(testname, "Max Version") {
			return "Max version|" + strconv.Itoa(int(httpsRequest.MaxVersion)) + "|" + strings.Replace(httpsRequest.Servername, domain, "DOMAIN", -1), strconv.Itoa(int(httpsRequest.MaxVersion))
		} else if strings.Contains(testname, "CipherSuite Alternate") {
			return "CipherSuite Alternate|" + strconv.Itoa(int(httpsRequest.CipherSuites[0])) + "|" + strings.Replace(httpsRequest.Servername, domain, "DOMAIN", -1), strconv.Itoa(int(httpsRequest.CipherSuites[0]))
		} else if strings.Contains(testname, "Client Certificate") {
			cert := httpsRequest.Certificate[0]
			c, _ := x509.ParseCertificate(cert.Certificate[0])
			return "Client Certificate|" + strings.Replace(c.Subject.CommonName, domain, "DOMAIN", -1) + "|" + strings.Replace(httpsRequest.Servername, domain, "DOMAIN", -1), strings.Replace(c.Subject.CommonName, domain, "DOMAIN", -1)
		}
	}
	return "", strategy
}

func FormatResponse(response interface{}, protocol string) string {
	formattedResponse := ""
	if response == nil {
		return formattedResponse
	}
	if protocol == "http" {
		return response.(string)
	} else {
		var httpsResponse util.TLSdata
		requstByte, err := json.Marshal(response)
		if err != nil {
			log.Fatal(err)
		}
		json.Unmarshal(requstByte, &httpsResponse)
		if httpsResponse.HandshakeComplete {
			return "Handshake complete | " + httpsResponse.HTTPResponse.(string)
		} else {
			return "Handshake incomplete"
		}
	}
	return formattedResponse
}

type anyType struct{ f1 string }

func analyze(fuzz_file string) []*Output {
	infile := util.OpenFileforRead(fuzz_file)
	scanner := bufio.NewScanner(infile)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	var outputs []*Output
	db, err := initializeASNDB()
	if err != nil {
		log.Fatal(err)
	}
	geolocate.Initialize(config.MaxmindFile)
	fingerprints := readSignaturePatterns(config.Infile)
	fingerprintOrder := make([]string, len(fingerprints))
	i := 0
	for k := range fingerprints {
		fingerprintOrder[i] = k
		i++
	}
	//Sort to map the blockpage strings in the right order
	sort.Strings(fingerprintOrder)
	alreadyDone := make(map[string]string)
	normalCensored := make(map[string]string)
	for scanner.Scan() {
		var input *util.Result
		line := scanner.Text()
		d := json.NewDecoder(strings.NewReader(line))
		d.UseNumber()
		if err := d.Decode(&input); err != nil {
			log.Println(line)
			log.Fatal("Could not unmarshal json: " + err.Error())
		}

		output := &Output{
			DstIP:                 input.IP,
			Domain:                input.Domain,
			TestName:              input.TestName,
			IsNormal:              input.IsNormal,
			MatchesNormal:         input.MatchesNormal,
			MatchesUncensored:     input.MatchesUncensored,
			NormalDifferences:     input.NormalDifferences,
			UncensoredDifferences: input.UncensoredDifferences,
			StartTime:             input.StartTime.Format("2006-01-02T15:04:05"),
			EndTime:               input.EndTime.Format("2006-01-02T15:04:05"),
		}
		filename := strings.Split(fuzz_file, "/")
		output.Country, output.MeasurementType, output.Protocol = split(filename[len(filename)-1])
		if output.Country == "blockpages" {
			output.MeasurementType = "blockpage"
			country, err := geolocate.Geolocate(input.IP)
			if err != nil {
				log.Printf("Cound not find country: " + err.Error())
			}
			output.Country = strings.ToLower(country)
		}
		if input.Error == nil {
			output.Error = ""
		} else {
			output.Error = input.Error.(string)
		}
		if input.UncensoredError == nil {
			output.UncensoredError = ""
		} else {
			output.UncensoredError = input.UncensoredError.(string)
		}
		output.Response = FormatResponse(input.Response, output.Protocol)
		output.UncensoredResponse = FormatResponse(input.UncensoredResponse, output.Protocol)
		if input.IsNormal == true {
			output.NormalResponseType = responsetype(output.Error, output.Response, fingerprintOrder, fingerprints)
			if (strings.Contains(output.NormalResponseType, "read") || strings.Contains(output.NormalResponseType, "write") || strings.Contains(output.NormalResponseType, "content")) && (strings.Contains(output.NormalResponseType, "rst") || strings.Contains(output.NormalResponseType, "timeout") || strings.Contains(output.NormalResponseType, "blockpage")) {
				normalCensored[output.Domain+"-"+output.Country+"-"+output.DstIP] = output.NormalResponseType
			}
		}
		if normalCensored[output.Domain+"-"+output.Country+"-"+output.DstIP] != "" {
			output.NormalCensored = true
		}

		output.CensorResponseType = responsetype(output.Error, output.Response, fingerprintOrder, fingerprints)
		output.UncensoredResponseType = responsetype(output.UncensoredError, output.Response, fingerprintOrder, fingerprints)

		//Fix matching bug in HTTPS
		if output.NormalCensored && output.Protocol == "https" && output.CensorResponseType == normalCensored[output.Domain+"-"+output.Country+"-"+output.DstIP] {
			output.MatchesNormal = true
		}

		output.TestID = output.Domain + "-" + output.Country + "-" + output.DstIP + "-" + output.TestName + "-" + strconv.FormatBool(output.IsNormal) + "-" + strconv.Itoa(rand.Intn(1000))
		ip := net.ParseIP(output.DstIP)
		as, _ := db.Lookup(ip)
		output.DstASN = as.Number
		output.Request, output.RequestStrategy = Strategy(input.TestName, output.Protocol, input.Domain, input.Request)
		output.UncensoredRequest, output.UncensoredRequestStrategy = Strategy(input.TestName, output.Protocol, "www.example.com", input.UncensoredRequest)
		if _, ok := alreadyDone[output.DstIP+output.Domain+output.TestName+output.Request]; !ok {
			outputs = append(outputs, output)
		}
		alreadyDone[output.DstIP+output.Domain+output.TestName+output.Request] = "Done"
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return outputs
}

func main() {
	log.Printf("Starting fuzz data analysis, looking into: " + config.Dir)
	files, err := filepath.Glob(config.Dir + "/*_fuzz.json")
	if err != nil {
		log.Fatal("Could not get files")
	}
	if len(files) == 0 {
		log.Fatal("No file found in directory")
	}
	outfile := util.CreateFile(config.AnalyzeOutfile)
	for _, filename := range files {
		log.Printf("File: " + filename)
		outputs := analyze(filename)
		for _, output := range outputs {
			data, err := json.Marshal(output)
			if err != nil {
				log.Println(err.Error())
				continue
			}
			data = append(data, byte('\n'))
			n, err := outfile.Write(data)
			if err != nil || n != len(data) {
				log.Println(err.Error())
			}
		}
	}

	log.Printf("Data written into JSON file")
	if config.Bigquery {
		log.Printf("Uploading JSON to bigquery")
		err = bigquery_upload.JSONtoBigquery(config.AnalyzeOutfile)
		if err != nil {
			log.Fatal("Could not write to bigquery: " + err.Error())
		}
		log.Printf("Data uploaded to bigquery")
	}
}
