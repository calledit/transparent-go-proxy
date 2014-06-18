package main

import (
	//"bytes"
	//"errors"
	//"io"
	//"io/ioutil"
	"log"
	"crypto/tls"
	"net"
	//"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

var ConID int
var ApprovedSenders []string


var TLSconfig *tls.Config


func HandleHTTPClient(Sc *httputil.ServerConn, ThisClient int, ClientId string, Scheme string) {

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
		r.URL.Scheme = Scheme

		FullUl := r.Host + r.URL.String()
		log.Println(ThisClient, "URL", FullUl)
		//Infotext := "You tried to download: '" + FullUl + "'.\n"

		if HasConnected == false {
			HasConnected = true

			DestinationAddress := r.URL.Host + ":" + r.URL.Scheme
			NetServerConnection, err := net.Dial("tcp", DestinationAddress)
			if err != nil {
				log.Println("could not connect to server:", DestinationAddress)
				return
			}
			if Scheme == "https" {
				TlsConenction := tls.Client(NetServerConnection, TLSconfig)
				ServerConnection = httputil.NewClientConn(TlsConenction, nil)
			} else {
				ServerConnection = httputil.NewClientConn(NetServerConnection, nil)
			}
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

type ConenctionHandler func(*net.TCPConn, int)

/*
 httpConHandler creates a HTTP conenction from a tcp conenction
*/
func httpConHandler(TcpConnection *net.TCPConn, ConID int) {

	//Handle Http stuff
	HttpReader := httputil.NewServerConn(TcpConnection, nil)
	HandleHTTPClient(HttpReader, ConID, TcpConnection.RemoteAddr().String(), "http")
}


/*
 TLSConHandler creates a HTTP conenction from a tls tcp conenction
*/
func TLSConHandler(TcpConnection *net.TCPConn, ConID int) {


	//Applt tls encryption
	TlsConenction := tls.Server(TcpConnection, TLSconfig)

	//Handle Http stuff
	HttpReader := httputil.NewServerConn(TlsConenction, nil)
	HandleHTTPClient(HttpReader, ConID, TcpConnection.RemoteAddr().String(), "https")
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
	HttpSocketAddress, _ := net.ResolveTCPAddr("tcp", ":80")
	HttpSocket, err := net.ListenTCP("tcp", HttpSocketAddress)
	if err != nil {
		panic(err)
	}
	defer HttpSocket.Close()
	go AcceptConenctions(HttpSocket, httpConHandler)

	//Load The Cert
	TLSconfig = &tls.Config{}
	TLSconfig.NextProtos = []string{"http/1.1"}
	TLSconfig.Certificates = make([]tls.Certificate, 1)
	TLSconfig.Certificates[0], err = tls.LoadX509KeyPair("snake.crt", "snake.key")
	if err != nil {
		panic(err)
	}

	/*
	Open Listener for https conenctions
	*/

	HttpsSocketAddress, _ := net.ResolveTCPAddr("tcp", ":443")
	HttpsSocket, err := net.ListenTCP("tcp", HttpsSocketAddress)
	if err != nil {
		panic(err)
	}
	//tlsListener := &tls.NewListener(HttpsSocket, config)
	defer HttpsSocket.Close()
	AcceptConenctions(HttpsSocket, TLSConHandler)

}
