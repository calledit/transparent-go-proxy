package main

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

type ScriptInserter struct {
	Browser     io.Writer
	HasInserted bool
}

type BlockString struct {
	Text    string
	NotText string
}

var ConID int
var IsInAmerica bool
var AmericanSites []string
var ApprovedSenders []string

func (ins *ScriptInserter) Write(p []byte) (n int, err error) {
	Befn := 0
	if !ins.HasInserted {
		pos := bytes.Index(p, []byte("</head>"))
		if pos != -1 {
			Befn, err = ins.Browser.Write(p[0:pos])
			if err != nil {
				return Befn, err
			}
			p = p[Befn:]

			log.Println("Inserting script tag.")
			n, err = ins.Browser.Write([]byte("<script src=\"http://172.32.1.1/inject/o.js\"></script>"))
			if err != nil {
				log.Println("Trying to write the script insert but could not complete, Result = fucked up webpage.")
				panic(err)
			}
			ins.HasInserted = true
		}
	}
	n, err = ins.Browser.Write(p)
	return n + Befn, err
}

func httpConHandler(rw *net.TCPConn, ConID int, DestinationAddress string) {
	Sc := httputil.NewServerConn(rw, nil)
	HandleClient(Sc, ConID, DestinationAddress)
}
func HandleClient(Sc *httputil.ServerConn, ThisClient int, DestinationAddress string) {

	DontRemoveCompressonOn := []string{"image", "audio", "video"}
	UrlBlocks := []BlockString{{".ad", ".add"}, {"/ad", "/add"}, {Text: "poker"}, {Text: "track"}, {Text: "facebook."}, {Text: "apple-touch-icon-precomposed.png"}, {Text: "annotations_invideo"}}

	HasConnected := false
	var ServerConnection *httputil.ClientConn

	defer Sc.Close()
	for {

		//Wait untill the client sends a new request
		r, err := Sc.Read()
		//Client closed the conenction
		if err != nil {
			return
		}

		//fix difrences in incoming and outgoing http.Request
		r.RequestURI = ""
		r.URL.Host = r.Host
		r.URL.Scheme = "http"

		//Block any websites that contain blocked words in their url
		UrlString := r.URL.String()
		Blocked := false
		for _, BlockString := range UrlBlocks {
			if strings.Contains(UrlString, BlockString.Text) {
				if BlockString.NotText == "" || !strings.Contains(UrlString, BlockString.NotText) {
					Infotext := "Blocked: '" + BlockString.Text + "' in url."
					resp := &http.Response{
						Status:        "410 Gone",
						StatusCode:    410,
						ContentLength: int64(len(Infotext)),
						Body:          ioutil.NopCloser(strings.NewReader(Infotext)),
						Proto:         "HTTP/1.1",
						ProtoMajor:    1,
						ProtoMinor:    1,
						Header:        make(http.Header),
						Close:         false,
					}
					resp.Header.Set("Content-Type", "text/html")
					log.Println(ThisClient, "Blocked:", r.URL, BlockString.Text, "in url")
					Sc.Write(r, resp)
					Blocked = true
					break
				}
			}
		}
		//Skip the rest of this request as we have alredy answerd it
		if Blocked {
			continue
		}

		log.Println(ThisClient, "URL", r.URL)

		//We remove compression on Requests that we might want to alter
		RemoveCommpression := true
		if val, ok := r.Header["Accept"]; ok {
			for _, vv := range val {
				for _, ContType := range DontRemoveCompressonOn {
					if strings.Contains(vv, ContType) {
						RemoveCommpression = false
					}
				}
			}
		}
		if RemoveCommpression {
			r.Header.Del("Accept-Encoding")
		}
		if HasConnected == false {

			//If we are to use http headers as the destination address
			if DestinationAddress == "" {
				DestinationAddress = r.URL.Host + ":" + r.URL.Scheme
			}

            DestinationAddress = FilterAmericanSites(DestinationAddress, "avpsserver.example.com:80")
	        if DestinationAddress == "" {
		        return
	        }

			NetServerConnection, err := net.Dial("tcp", DestinationAddress)
			if err != nil {
				log.Println("could not connect to server:", DestinationAddress)
				return
			}
			HasConnected = true
			ServerConnection = httputil.NewClientConn(NetServerConnection, nil)
			defer ServerConnection.Close()
		}

		//Lets get the stuff from our server
		resp, err := ServerConnection.Do(r)
		if err != nil && err != httputil.ErrPersistEOF {
			log.Println("Server did not answer nicly on our request:", r.URL.Host)
			return
		}

		if resp.ContentLength == 0 {
			//There is a bug in some subsystem here that causes one to have to set The encoding to identity when the size is zero
			resp.TransferEncoding = []string{"identity"}
		}

		Sc.Write(r, resp)
	}
}

func FilterAmericanSites(DestinationAddress string, ProxyServer string) string {
    IsAmericanSite := false
	for _, AmericanSite := range AmericanSites {
		if strings.Contains(DestinationAddress, AmericanSite) {
            IsAmericanSite = true
            if !IsInAmerica {
			    log.Println("Tuneling:", DestinationAddress)
			    return ProxyServer
            }
		}
	}
    if IsInAmerica && !IsAmericanSite {
		log.Println(ConID, "American Server can only access american sites")
        return ""
    }
    return DestinationAddress
}

func TLSConHandler(rw *net.TCPConn, ConID int, DestinationAddress string) {
	defer rw.Close()
	tlsmesage := make([]byte, 2048)
	rlen, _ := rw.Read(tlsmesage)
	if rlen > 42 && tlsmesage[0] == 0x16 && tlsmesage[5] == 0x01 {
		//If we are to use TLS SNI Extention header as the destination address
		ExtractedHost := clientHelloMsg(tlsmesage[5:rlen])

		if ExtractedHost == "" {
			log.Println(ConID, "Could not find SNI")
		} else if DestinationAddress == "" {
			DestinationAddress = ExtractedHost + ":https"
		} else {
			log.Println(ConID, "ExtractedHost: ", ExtractedHost)
		}
	} else {
		log.Println(ConID, "Not a client message")
	}
	if DestinationAddress == "" {
		return
	}
	log.Println(ConID, "TLS:", DestinationAddress)
    DestinationAddress = FilterAmericanSites(DestinationAddress, "avpsserver.example.com:443")
	if DestinationAddress == "" {
		return
	}
	TcpProxy(rw, ConID, DestinationAddress, tlsmesage[:rlen])
}


func GetLogPameters(loglisten *net.UDPConn) (LogMap map[string]string, err error) {
	logmesage := make([]byte, 512)
	loglen, _, err := loglisten.ReadFromUDP(logmesage)
	if err != nil {
		log.Println("udp read fail: %s", err)
		return nil, err
	}
	LogParts := strings.Split(string(logmesage[0:loglen]), "] FIREWALL PROXY ")
	if len(LogParts) != 2 {
		return nil, errors.New("Could not parse log")
	}
	LogParameters := strings.Split(LogParts[1], " ")
	LogMap = make(map[string]string, len(LogParameters))
	for _, LogPar := range LogParameters {
		LogVals := strings.Split(LogPar, "=")
		if len(LogVals) > 1 {
			LogMap[LogVals[0]] = LogVals[1]
		} else {
			LogMap[LogVals[0]] = ""
		}
	}
	return LogMap, nil
}

type ConenctionHandler func(*net.TCPConn, int, string)

func AcceptConenctions(l *net.TCPListener, loglisten *net.UDPConn, conH ConenctionHandler) {
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
        
        //Accept new conenctions and handle errors they may cause
		rw, e := l.AcceptTCP()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			panic(e)
		}
		tempDelay = 0

        //Check if the sender is on the aproved sender list if the list exists
		Approved := false
		if len(ApprovedSenders) != 0 {
			RemoteIP := rw.RemoteAddr().String()
			for _, ApprovedSender := range ApprovedSenders {
				if strings.Contains(RemoteIP, ApprovedSender) {
					Approved = true
					break
				}
			}
		} else {
			Approved = true
		}

        //Let the sender go if it was not on the approved list
		if !Approved {
			rw.SetLinger(0)
			rw.Close()
			continue
		}

		//Try to get a destination address from IPtables
		DestinationAddress := ""
		if loglisten != nil {
			LogMap, err := GetLogPameters(loglisten)
			if err == nil {
				if DestPort, ok := LogMap["DPT"]; ok {
					if DestServ, ok := LogMap["DST"]; ok {
						DestinationAddress = DestServ + ":" + DestPort
						log.Println(ConID+1, "Org:", DestinationAddress)
					}
				}
			}
		}

        //Give the connection away to a forutine that will handle it
		ConID++
		go conH(rw, ConID, DestinationAddress)
	}
}


func main() {
	ConID = 0
    IsInAmerica = false
	AmericanSites = []string{"netflix.com"}
	ApprovedSenders = []string{}

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:48786")
	loglisten, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Println("Could not listen to log messages Using http headers instead:", err)
	}
	defer loglisten.Close()

	loglisten = nil
	TcAd, _ := net.ResolveTCPAddr("tcp", ":8181")
	l, err := net.ListenTCP("tcp", TcAd)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	go AcceptConenctions(l, loglisten, httpConHandler)

	TcAdT, _ := net.ResolveTCPAddr("tcp", ":8182")
	ltls, err := net.ListenTCP("tcp", TcAdT)
	if err != nil {
		panic(err)
	}
	defer ltls.Close()
	AcceptConenctions(ltls, loglisten, TLSConHandler)

}

func clientHelloMsg(data []byte) string {
	if len(data) < 42 {
		return ""
	}
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return ""
	}
	data = data[39+sessionIdLen:]
	if len(data) < 2 {
		return ""
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return ""
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return ""
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return ""
	}

	data = data[1+compressionMethodsLen:]

	if len(data) < 2 {
		return ""
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return ""
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return ""
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return ""
		}

		if extension == 0 {
			if length < 2 {
				return ""
			}
			numNames := int(data[0])<<8 | int(data[1])
			d := data[2:]
			for i := 0; i < numNames; i++ {
				if len(d) < 3 {
					return ""
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return ""
				}
				if nameType == 0 {
					return string(d[0:nameLen])
				}
				d = d[nameLen:]
			}
		}
		data = data[length:]
	}
	return ""
}

func CopyCD(In *net.TCPConn, Out *net.TCPConn) {
	for {
		data := make([]byte, 256)
		n, err := In.Read(data)
		if err != nil {
			return
		}
		n, err = Out.Write(data[:n])
		if err != nil {
			return
		}
	}

}

func TcpProxy(Sc *net.TCPConn, ThisClient int, DestinationAddress string, AddData []byte) {
	TcAd, _ := net.ResolveTCPAddr("tcp", DestinationAddress)
	NetServerConnection, err := net.DialTCP("tcp", nil, TcAd)
	if err != nil {
		log.Println(ThisClient, "could not connect to server:", DestinationAddress)
		return
	}
	NetServerConnection.Write(AddData)
	defer NetServerConnection.Close()

	go CopyCD(NetServerConnection, Sc)
	CopyCD(Sc, NetServerConnection)

}
