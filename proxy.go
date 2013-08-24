package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"strings"
)

type ScriptInserter struct {
	Browser     io.Writer
	HasInserted bool
}

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

			n, err = ins.Browser.Write([]byte("<script src=\"http://172.32.1.1/flash_killer/o.js\"></script>"))
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

func PageRequested(w http.ResponseWriter, r *http.Request) {

	DontRemoveCompressonOn := []string{"image", "audio", "video"}
	UrlBlocks := []string{"/ad", "poker", "track", "facebook.", "apple-touch-icon-precomposed.png'"}
	//fix difrences in incoming and outgoing http.Request
	r.RequestURI = ""
	r.URL.Host = r.Host
	r.URL.Scheme = "http"

	for _, BlockString := range UrlBlocks {
		if strings.Contains(r.URL.String(), BlockString) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(410)
			w.Write([]byte("Blocked: '" + BlockString + "' in url."))
			return
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
	tr := &http.Transport{}
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
	//no Idea to inssert stuff if it is commpressed
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

func main() {
	http.HandleFunc("/", PageRequested)
	http.ListenAndServe(":8181", nil)
}
