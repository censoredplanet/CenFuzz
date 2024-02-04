package connection

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/censoredplanet/CenFuzz/config"
	"github.com/censoredplanet/CenFuzz/util"
	reuseport "github.com/libp2p/go-reuseport"
	utls "github.com/refraction-networking/utls"
)

type Connection struct {
	Host string
	Raw  *net.TCPConn
	Err  error
}

func NewConnection(host string, port uint) *Connection {
	conn := &Connection{
		Host: host,
	}

	raw, err := Dial(host, port)
	if err != nil {
		conn.handleError(err)
		//log.Println("Error in creating connection: ", err)
		return nil
	}
	conn.Raw = raw

	return conn
}

// SrcIP returns the IPv4 address for the input interface.
func SrcIP() string {
	//See if source IP is specified
	if config.Srcip != "" {
		return config.Srcip + ":0"
	} else if config.Iface == "" {
		// Detect interface information
		iface, err := net.InterfaceByName(config.Iface)
		if err != nil {
			log.Println("Connection.SrcIP: Warning: Picking default src IP, Could not open interface:", err.Error())
		}
		ipaddress := "0.0.0.0:0"
		if err != nil {
			log.Println("Connection.SrcIP: Warning: Picking default src IP, Could not open interface:", err.Error())
		}

		// Get addresses for interface
		addrs, err := iface.Addrs()
		if err != nil {
			log.Println("Connection.SrcIP: Warning: Picking default src IP, Could not get interface address", err.Error())
			return ipaddress
		}
		if len(addrs) == 0 {
			log.Println("Connection.SrcIP: Warning: Picking default src IP, Could not find address for interface: ", config.Iface)
			return ipaddress
		}

		// Return first IPv4 address that works
		for ip := range addrs {
			if ipaddr := addrs[ip].(*net.IPNet).IP.To4(); ipaddr != nil {
				return ipaddr.String() + ":0"
			}
		}
	}
	return "0.0.0.0:0"
}

func Dial(host string, port uint) (*net.TCPConn, error) {
	//log.Printf("Connecting to %s ...", host)
	var conn net.Conn
	var err error
	srcIP := SrcIP()
	conn, err = reuseport.Dial("tcp", srcIP,
		fmt.Sprintf("%s:%d", host, port))
	if conn == nil {
		return nil, err
	}
	connSetLinger := conn.(*net.TCPConn)
	if err := connSetLinger.SetLinger(0); err != nil {
		return nil, err
	}
	//log.Printf("Connected to %s ...", host)
	return connSetLinger, err
}

func SendHTTPRequest(conn *Connection, request string) interface{} {
	defer conn.Raw.Close()
	sent := []byte(request)
	if _, err := conn.Raw.Write(sent); err != nil {
		err = conn.handleError(err)
		return nil
	}

	if err := conn.Raw.CloseWrite(); err != nil {
		err = conn.handleError(err)
		return nil

	}

	maxResponseLength := 1 << 16
	response := make([]byte, maxResponseLength)

	responseLength := 0
	for {
		// TODO(adrs): add to config
		conn.Raw.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Raw.Read(response[responseLength:maxResponseLength])
		if err == io.EOF {
			break
		} else if err != nil {
			err = conn.handleError(err)
			break
		}
		responseLength += n
	}

	return string(response[:responseLength])
}

func SendHTTPSRequest(conn *Connection, tlsconfig utls.Config) *util.TLSdata {
	defer conn.Raw.Close()
	conn.Raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	var tlsConn *utls.UConn
	if config.Randomized {
		tlsConn = utls.UClient(conn.Raw, &tlsconfig, utls.HelloRandomized)
	} else {
		tlsConn = utls.UClient(conn.Raw, &tlsconfig, utls.HelloGolang)
	}
	defer tlsConn.Close()
	//Use refraction networking's utls instead of using crypto/tls to have more flexibility
	err := tlsConn.BuildHandshakeState()
	if err != nil {
		err = conn.handleError(err)
		return nil
	}
	err = tlsConn.Handshake()
	if err != nil {
		err = conn.handleError(err)
		return nil
	}

	state := tlsConn.ConnectionState()

	tlsData := &util.TLSdata{
		Version:                    state.Version,
		HandshakeComplete:          state.HandshakeComplete,
		CipherSuite:                state.CipherSuite,
		NegotiatedProtocol:         state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual: state.NegotiatedProtocolIsMutual,
		PeerCertificates:           state.PeerCertificates[0].Raw,
		ServerName:                 state.ServerName,
	}

	getRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost:%s\r\nConnection: close\r\n\r\n", tlsconfig.ServerName)
	_, err = tlsConn.Write([]byte(getRequest))
	if err != nil {
		err = conn.handleError(err)
		return tlsData
	}
	maxResponseLength := 1 << 16
	httpResponse := make([]byte, maxResponseLength)

	responseLength := 0
	for {
		// TODO(adrs): add to config
		tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := tlsConn.Read(httpResponse[responseLength:maxResponseLength])
		if err == io.EOF {
			break
		} else if err != nil {
			err = conn.handleError(err)
			return tlsData
		}
		responseLength += n
	}
	tlsData.HTTPResponse = string(httpResponse[:responseLength])
	return tlsData
}

func (conn *Connection) handleError(err error) error {
	if err != nil {
		//log.Println("Error in connection: ", err)
		conn.Err = err
		if conn.Raw != nil {
			conn.Raw.Close()
		}
	}
	return err
}
