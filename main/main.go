package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
	"github.com/thinkberg/ubirch-protocol-go/ubirch"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func saveProtocolContext(p *ubirch.Protocol) error {
	contextBytes, _ := json.Marshal(p)
	err := ioutil.WriteFile("../protocol.json", contextBytes, 444)
	if err != nil {
		log.Printf("unable to store protocol context: %v", err)
		return err
	} else {
		log.Printf("saved protocol context")
		return nil
	}
}

func loadProtocolContext(p *ubirch.Protocol) error {
	contextBytes, err := ioutil.ReadFile("../protocol.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(contextBytes, p)
	if err != nil {
		log.Fatalf("unable to deserialize context: %v", err)
		return err
	} else {
		log.Printf("loaded protocol context")
		log.Println(p.Signatures)
		return nil
	}
}

// configuration of the device
type config struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	KeyService string `json:"keyService"`
	Niomon     string `json:"niomon"`
	Data       string `json:"data"`
}

// load the configuration
func loadConfig(c *config) error {
	contextBytes, err := ioutil.ReadFile("../config.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(contextBytes, c)
	if err != nil {
		log.Fatalf("unable to deserialize context: %v", err)
		return err
	} else {
		log.Printf("loaded protocol context")
		return nil
	}
}

/*!
UDP connection handling.
Receive from and reply to the UDP client.
*/
func handleUDPConnection(conn *net.UDPConn) {

	// here is where you want to do stuff like read or write to client

	buffer := make([]byte, 1024)

	n, addr, err := conn.ReadFromUDP(buffer)

	fmt.Println("UDP client : ", addr)
	fmt.Println("Received from UDP client :  ", string(buffer[:n]))
	fmt.Println(buffer[:n])

	if err != nil {
		log.Fatal(err)
	}

	// NOTE : Need to specify client address in WriteToUDP() function
	//        otherwise, you will get this error message
	//        write udp : write: destination address required if you use Write() function instead of WriteToUDP()

	// write message back to client
	message := []byte("Hello UDP client!")
	_, err = conn.WriteToUDP(message, addr)

	if err != nil {
		log.Println(err)
	}

}

func udpConnect() {
	hostName := "192.168.1.126"
	portNum := "15001"
	service := hostName + ":" + portNum

	udpAddr, err := net.ResolveUDPAddr("udp4", service)

	if err != nil {
		log.Fatal(err)
	}

	// setup listener for incoming UDP connection
	ln, err := net.ListenUDP("udp", udpAddr)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("UDP server up and listening on port 15001")

	defer ln.Close()

	for {
		// wait for UDP client to connect
		handleUDPConnection(ln)
	}
}

func main() {
	// creata a name
	name := "A"
	// create a Crypto context
	context := &ubirch.CryptoContext{&keystore.Keystore{}, map[string]uuid.UUID{}}
	// create a ubirch Protocol
	p := ubirch.Protocol{
		Crypto:     context,
		Signatures: map[uuid.UUID][]byte{},
	}
	conf := config{
		Username:   "",
		Password:   "",
		KeyService: "",
		Niomon:     "",
		Data:       "",
	}

	err := loadConfig(&conf)
	if err != nil {
		log.Printf("conf not found, or unable to load: %v", err)
	}

	// load the Protocol and if it is not available, create a new one
	err = loadProtocolContext(&p)
	if err != nil {
		log.Printf("keystore not found, or unable to load: %v", err)
		uid, _ := uuid.Parse(conf.Username)
		err = p.GenerateKey(name, uid)
		if err != nil {
			log.Fatalf("can't add key to key store: %v", err)
		}
	}

	data, _ := hex.DecodeString("010203040506070809FF")
	encoded, err := p.Sign(name, data, ubirch.Chained)
	if err != nil {
		log.Fatalf("creating signed upp failed: %v", err)
	}
	log.Print(hex.EncodeToString(encoded))

	go func() {
		log.Println("Listening signals...")
		c := make(chan os.Signal, 1) // we need to reserve to buffer size 1, so the notifier are not blocked
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	}()

	_ = saveProtocolContext(&p)

	uid, _ := uuid.Parse(conf.Username)

	cert, err := getSignedCertificate(&p, name, uid)
	if err != nil {
		log.Printf("could not generate certificate: %v", err)
	} else {
		log.Printf("certificate: %s", string(cert))
	}

	auth := fmt.Sprintf("%s:%s", conf.Username, conf.Password)
	log.Println("combined ", auth)
	sEnc := base64.StdEncoding.EncodeToString([]byte(auth))
	log.Println("base64:", sEnc)

	// todo this post will be included later
	//
	// resp, err := post(cert,
	//         fmt.Sprintf("%spubkey", conf.KeyService),
	//         sEnc,
	//         map[string]string{"Content-Type": "application/json"})
	//
	// if err != nil {
	//         log.Printf("unable to read response body: %v", err)
	// } else {
	//         log.Printf("response: %s", string(resp))
	// }

	//// test json to understand
	// type ColorGroup struct {
	//         ID     int
	//         Name   string
	//         Colors []string
	// }
	// group := ColorGroup{
	//         ID:     1,
	//         Name:   "Reds",
	//         Colors: []string{"Crimson", "Red", "Ruby", "Maroon"},
	// }
	// b, err := json.Marshal(group)
	// if err != nil {
	//         fmt.Println("error:", err)
	// }
	// log.Println("JSON TEST" , string(b))
	// type signature struct{
	//         name string
	//        data string
	// }
	// var Signature []signature
	// log.Println("SIGNATURE RAW", signature)
	// _, err = json.Unmarshal([]byte(b), &signature)
	// log.Println("SIGNATURE UNMARSHALED", string(signature))

	udpConnect()
}
