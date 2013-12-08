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
    //"crypto/tls"
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


func HandleClient(Sc *httputil.ServerConn, ThisClient int, DestinationServer string){


	DontRemoveCompressonOn := []string{"image", "audio", "video"}
	AmericanSites := []string{"netflix.com"}
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
                        Proto: "HTTP/1.0",
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
                    //continue
                }
            }
        }
        if Blocked {
            continue
        }
        //if HasConnected == false {
        //    log.Println("Client connected:", r.URL.Host)
        //    defer log.Println("Client disconected:", r.URL.Host)
        //}
        
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
            
            ServerName := DestinationServer;
            ServerPort := r.URL.Scheme
            for _, AmericanSite := range AmericanSites {
                if strings.Contains(ServerName, AmericanSite) {
                    log.Println("Forwarding to America:", r.URL.Host)
                    ServerName = "IPaddress to forward to"
                    ServerPort = "123";
                    break;
                }
            }

            NetServerConnection, err := net.Dial("tcp", ServerName+":"+ServerPort)
            if err != nil {
                log.Println("could not connect to server:", ServerName+":"+ServerPort)
                // handle error
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

func AcceptConenctions(l net.Listener, loglisten *net.UDPConn) {
    var tempDelay time.Duration // how long to sleep on accept failure
    for {
        rw, e := l.Accept()
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
                log.Printf("http: Accept error: %v; retrying in %v", e, tempDelay)
                time.Sleep(tempDelay)
                continue
            }
            panic(e)
        }
        tempDelay = 0
        logmesage := make([]byte, 512)
        loglen,_,err := loglisten.ReadFromUDP(logmesage)
        if err != nil {
            log.Fatalf("udp read fail: %s", err)
        }
        LogParts := strings.Split(string(logmesage[0:loglen]), "] FIREWALL PROXY ")
        if len(LogParts) != 2 {
            log.Fatalf("need 2 LogParts: %v", LogParts)
        }
        LogParameters := strings.Split(LogParts[1]," ")
        LogMap := make(map[string] string,len(LogParameters))
        for _, LogPar := range LogParameters {
            LogVals := strings.Split(LogPar, "=")
            if len(LogVals) > 1 {
                LogMap[LogVals[0]] = LogVals[1]
            }else{
                LogMap[LogVals[0]] = ""
            }
            
        }
        if val, ok := LogMap["DST"]; ok {
            log.Println(ConID + 1,"Log Dst:", val)
            Sc := httputil.NewServerConn(rw, nil)
            ConID++
            go HandleClient(Sc, ConID, val)
        }else{
            log.Fatalf("No Destination Paramer in log")
        }
        /*if usetls {
            log.Printf("Got Conenction: %+v", rw)
            cert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
            if err != nil {
                log.Fatalf("server: loadkeys: %s", err)
            }
            tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
            tlsrw := tls.Server(rw, &tlsConfig)
            rw = tlsrw
            HandErr := tlsrw.Handshake();
            ConSt := tlsrw.ConnectionState();
            log.Printf("HandErr: %+v, ConSt: %+v", HandErr, ConSt)
        }*/
    }
    
}

func main() {
	//tr = &http.Transport{}
    ConID = 0

    addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:48786")
    if err != nil {
        log.Fatalf("Could not resolve", err)
    }
    loglisten, err := net.ListenUDP("udp", addr)
    if err != nil {
        log.Fatalf("Could not listen to log messages", err)
    }

    l, err := net.Listen("tcp", ":8181")
    if err != nil {
        panic(err)
    }
    defer l.Close()
    AcceptConenctions(l, loglisten)

    /*ltls, err := net.Listen("tcp", ":8182")
    if err != nil {
        panic(err)
    }
    defer ltls.Close()
    AcceptConenctions(ltls, true)
    */
}
