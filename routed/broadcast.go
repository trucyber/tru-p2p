package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"io"
	// mrand "math/rand"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/libp2p/go-libp2p-peerstore"
	"github.com/multiformats/go-multiaddr"

	ds "github.com/ipfs/go-datastore"
	dsync "github.com/ipfs/go-datastore/sync"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	rhost "github.com/libp2p/go-libp2p/p2p/host/routed"
	ma "github.com/multiformats/go-multiaddr"
)

// BROADCAST
var rws []*bufio.ReadWriter
var dests []string //saves destinations of connected hosts

/*
* addAddrToPeerstore parses a peer multiaddress and adds
* it to the given host's peerstore, so it knows how to
* contact it. It returns the peer ID of the remote peer.
* @credit examples/http-proxy/proxy.go
 */
func addAddrToPeerstore(h host.Host, addr string) peer.ID {
	// The following code extracts target's the peer ID from the
	// given multiaddress
	ipfsaddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		log.Fatalln(err)
	}
	pid, err := ipfsaddr.ValueForProtocol(multiaddr.P_IPFS)
	if err != nil {
		log.Fatalln(err)
	}

	peerid, err := peer.IDB58Decode(pid)
	if err != nil {
		log.Fatalln(err)
	}

	// Decapsulate the /ipfs/<peerID> part from the target
	// /ip4/<a.b.c.d>/ipfs/<peer> becomes /ip4/<a.b.c.d>
	targetPeerAddr, _ := multiaddr.NewMultiaddr(
		fmt.Sprintf("/ipfs/%s", peer.IDB58Encode(peerid)))
	targetAddr := ipfsaddr.Decapsulate(targetPeerAddr)

	// We have a peer ID and a targetAddr so we add
	// it to the peerstore so LibP2P knows how to contact it
	h.Peerstore().AddAddr(peerid, targetAddr, peerstore.PermanentAddrTTL)
	return peerid
}

// func doBroadcast(s network.Stream) error{
// 	// Create a buffer stream for non blocking read and write.
// 	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
// 	rws = append(rws, rw)
// 	go readData(rw)
// 	go writeData(rw)
// }

func handleStream(s network.Stream) {
	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
	rws = append(rws, rw)
	go readData(rw)
	go writeData(rw)
}
func readData(rw *bufio.ReadWriter) {
	for {
		str, err := rw.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from buffer")
			panic(err)
		}

		if str == "" {
			return
		}
		if str != "\n" {
			// Green console colour:    \x1b[32m
			// Reset console colour:    \x1b[0m
			fmt.Printf("\x1b[32m%s\x1b[0m> ", str)
		}

	}
}

func writeData(rw *bufio.ReadWriter) {
	stdReader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		sendData, err := stdReader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from stdin")
			panic(err)
		}

		for _, rw := range rws {
			rw.WriteString(fmt.Sprintf("%s\n", sendData))
			rw.Flush()
		}
	}
}

// makeRoutedHost creates a LibP2P host with a random peer ID listening on the
// given multiaddress. It will use secio if secio is true. It will bootstrap using the
// provided PeerInfo
func makeRoutedHost(listenPort int, randseed int) (host.Host, error) {

	// If the seed is zero, use real cryptographic randomness. Otherwise, use a
	// deterministic randomness source to make generated keys stay the same
	// across multiple runs
	var r io.Reader
	if randseed == 0 {
		r = rand.Reader
	} 

	// Generate a key pair for this host. We will use it at least
	// to obtain a valid host ID.
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, r)
	if err != nil {
		return nil, err
	}

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort)),
		libp2p.Identity(priv),
		libp2p.DefaultTransports,
		libp2p.DefaultMuxers,
		libp2p.DefaultSecurity,
		libp2p.NATPortMap(),
	}

	ctx := context.Background()

	basicHost, err := libp2p.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	// Construct a datastore (needed by the DHT). This is just a simple, in-memory thread-safe datastore.
	dstore := dsync.MutexWrap(ds.NewMapDatastore())

	// Make the DHT
	dht := dht.NewDHT(ctx, basicHost, dstore)

	// Make the routed host
	routedHost := rhost.Wrap(basicHost, dht)

	// Build host multiaddress
	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", routedHost.ID().Pretty()))

	// Now we can build a full multiaddress to reach this host
	// by encapsulating both addresses:
	// addr := routedHost.Addrs()[0]
	addrs := routedHost.Addrs()
	log.Println("I can be reached at:")
	for _, addr := range addrs {
		log.Println(addr.Encapsulate(hostAddr))
	}

	log.Printf("Now run \"./routed-echo -l %d -d %s%s\" on a different terminal\n", listenPort+1, routedHost.ID().Pretty())

	return routedHost, nil
}

func main() {
	help := flag.Bool("help", false, "Display Help")
	flag := parseFlags()

	if *help {
		fmt.Printf("This program demonstrates a simple p2p broadcast application using libp2p and mDNS.\n\n")
		fmt.Printf("Usage: Run './broadcast2'\nor Run './broadcast2 -host [host] -port [port] -rendezvous [string] -pid [proto ID]'\n")

		os.Exit(0)
	}

	fmt.Printf("[*] Listening on: %s with port: %d\n", flag.listenHost, flag.listenF)

	ctx := context.Background()

	if flag.listenF == 0 {
		log.Fatal("Please provide a port to bind on with -l")
	}

	host, err := makeRoutedHost(flag.listenF, flag.seed)
	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		panic(err)
	}

	host.SetStreamHandler(protocol.ID(flag.ProtocolID), handleStream)

	fmt.Printf("\n[*] Your Multiaddress Is: /ip4/%s/tcp/%v/p2p/%s\n", flag.listenHost, flag.listenF, host.ID().Pretty())

	peerChan := initMDNS(ctx, host, flag.RendezvousString)
	peer := <-peerChan // will block untill we discover a peer

	maSplit := strings.Split(fmt.Sprintf("%s", peer), " ")
	ip := strings.Trim(maSplit[1], "[]}") + "/ipfs/"
	hostID := strings.Trim(maSplit[0], "{}:")
	ma := strings.Trim(ip+hostID, " ")

	fmt.Println("Found peer:", peer, ", connecting")

	if err := host.Connect(ctx, peer); err != nil {
		fmt.Println("Connection failed:", err)
	}

	if flag.cli == 1{

		// Add destination peer multiaddress in the peerstore.
		// This will be used during connection and stream creation by libp2p.
		peerID := addAddrToPeerstore(host, ma)

		// Start a stream with peer with peer Id: 'peerId'.
		// Multiaddress of the destination peer is fetched from the peerstore using 'peerId'.
		s, err := host.NewStream(ctx, peerID, "/broadcast/1.0.0")

		if err != nil {
			panic(err)
		}

		// Destination is a valid multiaddress
		dests = append(dests, ma)

		// Create a buffered stream so that read and writes are non blocking.
		rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
		rws = append(rws, rw)
		go writeData(rw)
		go readData(rw)

		host.SetStreamHandler("/broadcast/1.0.0", handleStream)
		select {}
	} else {
		addAddrToPeerstore(host, ma)
		select {}
	}

	//fmt.Printf("Run './broadcast -d /ip4/127.0.0.1/tcp/%d/ipfs/%s' on another console.\n You can replace 127.0.0.1 with public IP as well.\n\n", *sourcePort, host.ID().Pretty())

	// Hang forever.
	// select {}
}