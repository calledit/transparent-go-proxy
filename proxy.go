package main

import (
	"bytes"
	"io"
    "io/ioutil"
	"log"
	"net/http"
    "net/http/httputil"
    "time"
    "net"
    "errors"
	"strings"
)

type ScriptInserter struct {
	Browser     io.Writer
	HasInserted bool
}

type BlockString struct {
    Text string
    NotText string
}

var ConID int
var AmericanSites []string
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


func HandleClient(Sc *httputil.ServerConn, ThisClient int, DestinationAddress string){


	DontRemoveCompressonOn := []string{"image", "audio", "video"}
	UrlBlocks := []BlockString{{".ad",".add"},{"/ad","/add"}, {Text:"poker"}, {Text:"track"}, {Text:"facebook."}, {Text:"apple-touch-icon-precomposed.png"},{Text:"annotations_invideo"}}

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
                        Status: "410 Gone",
                        StatusCode: 410,
                        ContentLength: int64(len(Infotext)),
                        Body: ioutil.NopCloser(strings.NewReader(Infotext)),
                        Proto: "HTTP/1.1",
                        ProtoMajor: 1,
                        ProtoMinor: 1,
                        Header: make(http.Header),
                        Close: false,
                    }
                    resp.Header.Set("Content-Type", "text/html")
                    log.Println(ThisClient, "Blocked:", r.URL,BlockString.Text, "in url")
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

	    log.Println(ThisClient,"URL", r.URL)
        
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
                DestinationAddress = r.URL.Host+":"+r.URL.Scheme
            }
            
            //Should this connection be tunneld somewere elese
            for _, AmericanSite := range AmericanSites {
                if strings.Contains(r.URL.Host, AmericanSite) {
                    log.Println("Tuneling:", r.URL.Host)
                    DestinationAddress = "avpsserver.example.com:8181"
                    break;
                }
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

func GetLogPameters(loglisten *net.UDPConn) (LogMap map[string] string, err error){
    logmesage := make([]byte, 512)
    loglen,_,err := loglisten.ReadFromUDP(logmesage)
    if err != nil {
        log.Println("udp read fail: %s", err)
        return nil, err
    }
    LogParts := strings.Split(string(logmesage[0:loglen]), "] FIREWALL PROXY ")
    if len(LogParts) != 2 {
        return nil, errors.New("Could not parse log")
    }
    LogParameters := strings.Split(LogParts[1]," ")
    LogMap = make(map[string] string,len(LogParameters))
    for _, LogPar := range LogParameters {
        LogVals := strings.Split(LogPar, "=")
        if len(LogVals) > 1 {
            LogMap[LogVals[0]] = LogVals[1]
        }else{
            LogMap[LogVals[0]] = ""
        }
    }
    return LogMap, nil
}

type ConenctionHandler func(*net.TCPConn, int, string)
func AcceptConenctions(l *net.TCPListener, loglisten *net.UDPConn, conH ConenctionHandler) {
    var tempDelay time.Duration // how long to sleep on accept failure
    for {
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

        DestinationAddress := "" 
        //Try to get a destination address from IPtables
        if loglisten != nil {
            LogMap, err := GetLogPameters(loglisten)
            if err == nil {
                if DestPort, ok := LogMap["DPT"]; ok {
                    if DestServ, ok := LogMap["DST"]; ok {
                        DestinationAddress = DestServ+":"+DestPort
                        log.Println(ConID + 1,"Org:", DestinationAddress)
                    }
                }
            }
        }
        ConID++
        conH(rw, ConID, DestinationAddress)
    }
}
func TLSConHandler(rw *net.TCPConn,  ConID int, DestinationAddress string){
    tlsmesage := make([]byte, 2048)
    rlen, _ := rw.Read(tlsmesage)
    if(rlen > 10 && tlsmesage[0] ==  0x16 && tlsmesage[5] ==  0x01) {
        pos := bytes.LastIndex(tlsmesage, []byte{0x00, 0x0a, 0x00})
        if pos == -1 {
            log.Println(ConID, "No SNI tls extention")
        }else{
            firstpos := bytes.LastIndex(tlsmesage[0:pos], []byte{0x00})
            log.Println(ConID, "TLS:", string(tlsmesage[firstpos+2:pos]))
            //If we are to use TLS SNI Extention header as the destination address
            if DestinationAddress == "" {
                DestinationAddress = string(tlsmesage[firstpos+2:pos])+":https"
            }
        }
    }else{
        log.Println(ConID, "Not a client message")
    }
    for _, AmericanSite := range AmericanSites {
        if strings.Contains(DestinationAddress, AmericanSite) {
            log.Println("Tuneling:", DestinationAddress)
            DestinationAddress = "avpsserver.example.com:8182"
            break;
        }
    }
    go TcpProxy(rw, ConID, DestinationAddress, tlsmesage[:rlen])
}
func httpConHandler(rw *net.TCPConn,  ConID int, DestinationAddress string){
    Sc := httputil.NewServerConn(rw, nil)
    go HandleClient(Sc, ConID, DestinationAddress)
}

func CopyCD(In *net.TCPConn, Out *net.TCPConn){
    for {
        data := make([]byte, 256)
        n, err := In.Read(data)
        if err != nil {
            return
        }
        Out.Write(data[:n])
    }

}

func TcpProxy(Sc *net.TCPConn, ThisClient int, DestinationAddress string, AddData []byte){
    TcAd,_ := net.ResolveTCPAddr("tcp", DestinationAddress)
    NetServerConnection, err := net.DialTCP("tcp", nil, TcAd)
    if err != nil {
        log.Println(ThisClient, "could not connect to server:", DestinationAddress)
        return
    }
    NetServerConnection.Write(AddData)
    defer NetServerConnection.Close()
    defer Sc.Close()
    
    go CopyCD(NetServerConnection, Sc)
    CopyCD(Sc, NetServerConnection)

    
}

func main() {
    ConID = 0
	AmericanSites = []string{"netflix.com"}

    addr,_ := net.ResolveUDPAddr("udp", "127.0.0.1:48786")
    loglisten, err := net.ListenUDP("udp", addr)
    if err != nil {
        log.Println("Could not listen to log messages Using http headers instead:", err)
    }
    defer loglisten.Close()

    loglisten = nil
    TcAd,_ := net.ResolveTCPAddr("tcp", ":8181")
    l, err := net.ListenTCP("tcp", TcAd)
    if err != nil {
        panic(err)
    }
    defer l.Close()
    go AcceptConenctions(l, loglisten, httpConHandler)

    TcAdT,_ := net.ResolveTCPAddr("tcp", ":8182")
    ltls, err := net.ListenTCP("tcp", TcAdT)
    if err != nil {
        panic(err)
    }
    defer ltls.Close()
    AcceptConenctions(ltls, loglisten, TLSConHandler)

}
