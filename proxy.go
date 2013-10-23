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
/*
var tr *http.Transport
func PageRequested(w http.ResponseWriter, r *http.Request) {

	DontRemoveCompressonOn := []string{"image", "audio", "video"}
	UrlBlocks := []BlockString{{".ad",".add"},{"/ad","/add"}, {Text:"poker"}, {Text:"track"}, {Text:"facebook."}, {Text:"apple-touch-icon-precomposed.png"},{Text:"annotations_invideo"}}


	//fix difrences in incoming and outgoing http.Request
	r.RequestURI = ""
	r.URL.Host = r.Host
	r.URL.Scheme = "http"

    UrlString := r.URL.String()
	for _, BlockString := range UrlBlocks {
		if strings.Contains(UrlString, BlockString.Text) {
            if BlockString.NotText == "" || !strings.Contains(UrlString, BlockString.NotText) {
			    w.Header().Set("Content-Type", "text/html")
			    w.WriteHeader(410)
	            log.Println("Blocked:", r.URL,BlockString.Text, "in url")
			    w.Write([]byte("Blocked: '" + BlockString.Text + "' in url."))
			    return
            }
		}
	}
	log.Println("URL", r.URL)

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
	resp, err := tr.RoundTrip(r)
	if err != nil {
		panic(err)
	}
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Set(k, vv)
		}
	}

	w.WriteHeader(resp.StatusCode)

	TryToInsert := false
	//Dont to inssert stuff if the data is commpressed
	if RemoveCommpression {
		//We only want to insert in to html pages
		if val, ok := resp.Header["Content-Type"]; ok {
			for _, vv := range val {
				if strings.Contains(vv, "html") {
					TryToInsert = true
				}
			}
		}
	}

	if TryToInsert {
		TestW := ScriptInserter{w, false}
		io.Copy(&TestW, resp.Body)
	} else {
		io.Copy(w, resp.Body)
	}
	resp.Body.Close()
}
*/



func HandleClient(Sc *httputil.ServerConn){

    ThisClient := ConID
    ConID++    

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
            break
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
                        Close: true,
                    }
                    resp.Header.Set("Content-Type", "text/html")
                    log.Println("Blocked:", r.URL,BlockString.Text, "in url")
                    Blocked = true
                    Sc.Write(r, resp)
                    break
                }
            }
        }
        if Blocked == true {
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
            NetServerConnection, err := net.Dial("tcp", r.URL.Host+":"+r.URL.Scheme)
            if err != nil {
                // handle error
                return
            }
            HasConnected = true
            ServerConnection = httputil.NewClientConn(NetServerConnection, nil)
            defer ServerConnection.Close()
        }

        //Lets get the stuff from our server
	    resp, err := ServerConnection.Do(r) //ServerConector.RoundTrip(r)
	    if err != nil {
            return
	    }
        if resp.ContentLength == 0 {
            //There is a bug in some subsystem here that causes one to have to set The encoding to identity when the size is zero
            resp.TransferEncoding = []string{"identity"}
        }
        
        Sc.Write(r, resp)
    }
}

func main() {
	//tr = &http.Transport{}
    ConID = 0

    l, err := net.Listen("tcp", ":8181")
    if err != nil {
        panic(err)
    }
    defer l.Close()
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
        Sc := httputil.NewServerConn(rw, nil)
        go HandleClient(Sc)
    }
}
