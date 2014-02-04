package main

import (
	//"bytes"
	//"errors"
	//"io"
	"io/ioutil"
	"log"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

var ConID int
var ApprovedSenders []string


func HandleHTTPClient(Sc *httputil.ServerConn, ThisClient int, ClientId string) {

	//HasConnected := false
	//var ServerConnection *httputil.ClientConn

	defer Sc.Close()
	for {

		//Wait untill the client sends a new request
		r, err := Sc.Read()
		//Client closed the conenction
		if err != nil {
			return
		}
		FullUl := r.Host + r.URL.String()
		log.Println(ThisClient, "URL", FullUl)
		Infotext := "You tried to download: '" + FullUl + "'.\n"
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
		Sc.Write(r, resp)
	}
}

type ConenctionHandler func(*net.TCPConn, int)

/*
 httpConHandler creates a HTTP conenction from a tcp conenction
*/
func httpConHandler(TcpConnection *net.TCPConn, ConID int) {

	//Handle Http stuff
	HttpReader := httputil.NewServerConn(TcpConnection, nil)
	HandleHTTPClient(HttpReader, ConID, TcpConnection.RemoteAddr().String())
}


/*
 TLSConHandler creates a HTTP conenction from a tls tcp conenction
*/
func TLSConHandler(TcpConnection *net.TCPConn, ConID int) {

	//First Load The Cert
	var err error
	config := &tls.Config{}
	config.NextProtos = []string{"http/1.1"}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair("snake.crt", "snake.key")
	if err != nil {
		panic(err)
	}

	//Applt tls encryption
	TlsConenction := tls.Server(TcpConnection, config)

	//Handle Http stuff
	HttpReader := httputil.NewServerConn(TlsConenction, nil)
	HandleHTTPClient(HttpReader, ConID, TcpConnection.RemoteAddr().String())
}


func AcceptConenctions(NetworkListener *net.TCPListener, TcpHandler ConenctionHandler) {
	var tempDelay time.Duration // how long to sleep on accept failure
	for {

		//Accept new conenctions and handle errors they may cause
		TcpConnenction, e := NetworkListener.AcceptTCP()
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

		//XXXXXXX this approving stuff whill halt stuf as it is not paraleble
		//Check if the sender is on the aproved sender list if the list exists
		Approved := false
		if len(ApprovedSenders) != 0 {
			RemoteIP := TcpConnenction.RemoteAddr().String()
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
			TcpConnenction.SetLinger(0)
			TcpConnenction.Close()
			continue
		}

		//Give the connection away to a gorutine that will handle it
		ConID++
		go TcpHandler(TcpConnenction, ConID)
	}
}

func main() {
	ConID = 0
	ApprovedSenders = []string{}

	/*
	Open Listener for http conenctions
	*/
	HttpSocketAddress, _ := net.ResolveTCPAddr("tcp", ":8181")
	HttpSocket, err := net.ListenTCP("tcp", HttpSocketAddress)
	if err != nil {
		panic(err)
	}
	defer HttpSocket.Close()
	go AcceptConenctions(HttpSocket, httpConHandler)

	/*
	Open Listener for https conenctions
	*/

	HttpsSocketAddress, _ := net.ResolveTCPAddr("tcp", ":8182")
	HttpsSocket, err := net.ListenTCP("tcp", HttpsSocketAddress)
	if err != nil {
		panic(err)
	}
	//tlsListener := &tls.NewListener(HttpsSocket, config)
	defer HttpsSocket.Close()
	AcceptConenctions(HttpsSocket, TLSConHandler)

}
