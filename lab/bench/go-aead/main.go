// SPDX-License-Identifier: Apache-2.0
// Crypto-only baseline for the CPE comparison: the AEAD wireguard-go (and so wanflow-mesh) uses,
// golang.org/x/crypto chacha20poly1305, sealing then opening 1280-byte packets in place on one core,
// like flowmesh's dp_bench does with its own data path.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	n := 100000
	if len(os.Args) > 1 {
		n, _ = strconv.Atoi(os.Args[1])
	}
	key := make([]byte, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	plain := make([]byte, 1280)
	buf := make([]byte, 0, 1280+aead.Overhead())
	nonce := make([]byte, chacha20poly1305.NonceSize)
	var enc, dec time.Duration
	start := time.Now()
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint64(nonce[4:], uint64(i))
		t0 := time.Now()
		sealed := aead.Seal(buf[:0], nonce, plain, nil)
		t1 := time.Now()
		if _, err := aead.Open(sealed[:0], nonce, sealed, nil); err != nil {
			panic(err)
		}
		enc += t1.Sub(t0)
		dec += time.Since(t1)
	}
	total := time.Since(start)
	fmt.Printf("x/crypto chacha20poly1305, %d packets of 1280 B: %.0f kpkt/s, %.2f Gbit/s; seal %.0f ns/pkt, open %.0f ns/pkt\n",
		n, float64(n)/total.Seconds()/1e3, float64(n*1280*8)/total.Seconds()/1e9,
		float64(enc.Nanoseconds())/float64(n), float64(dec.Nanoseconds())/float64(n))
}
