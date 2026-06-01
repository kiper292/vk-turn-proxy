package main

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestWrapPacketListenerRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, wrapKeyLen)
	listener, err := listenWrapped(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}, key)
	if err != nil {
		t.Fatalf("listenWrapped: %v", err)
	}
	defer listener.Close()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer client.Close()

	request := []byte("client to server")
	if _, err := client.WriteToUDP(wrapForTest(t, key, request), listener.Addr().(*net.UDPAddr)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	serverConn, clientAddr, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverConn.Close()

	if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set server deadline: %v", err)
	}
	buf := make([]byte, 256)
	n, _, err := serverConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf[:n], request) {
		t.Fatalf("server plaintext = %q, want %q", buf[:n], request)
	}

	response := []byte("server to client")
	if _, err := serverConn.WriteTo(response, clientAddr); err != nil {
		t.Fatalf("server write: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	n, _, err = client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if plain := unwrapForTest(t, key, buf[:n]); !bytes.Equal(plain, response) {
		t.Fatalf("client plaintext = %q, want %q", plain, response)
	}
}

func TestNewWrapStateRejectsInvalidKey(t *testing.T) {
	if _, err := newWrapState(make([]byte, wrapKeyLen-1)); err == nil {
		t.Fatal("newWrapState accepted a short key")
	}
}

func wrapForTest(t *testing.T, key, payload []byte) []byte {
	t.Helper()

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("new AEAD: %v", err)
	}
	out := make([]byte, wrapOverhead+len(payload))
	out[0] = wrapRTPVersion
	out[1] = wrapRTPPT
	if _, err := rand.Read(out[2:wrapHeaderLen]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	nonce := out[wrapRTPHdrLen:wrapHeaderLen]
	copy(out[wrapHeaderLen:], payload)
	aead.Seal(out[wrapHeaderLen:wrapHeaderLen], nonce, out[wrapHeaderLen:wrapHeaderLen+len(payload)], out[:wrapHeaderLen])
	return out
}

func unwrapForTest(t *testing.T, key, wire []byte) []byte {
	t.Helper()

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("new AEAD: %v", err)
	}
	nonce := wire[wrapRTPHdrLen:wrapHeaderLen]
	plain, err := aead.Open(nil, nonce, wire[wrapHeaderLen:], wire[:wrapHeaderLen])
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	return plain
}
