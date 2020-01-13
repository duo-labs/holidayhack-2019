package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"io/ioutil"
	"sync"
	"time"
)

const KeySize = 8

var wg sync.WaitGroup

func prng(seed int) (int, int) {
	seed = seed*0x343fd + 0x269ec3
	return (seed >> 0x10 & 0x7fff), seed
}

func worker(tsChan <-chan int, done <-chan bool, ciphertext []byte) {
	defer wg.Done()
	key := make([]byte, KeySize)
	buf := make([]byte, len(ciphertext))
	for {
		select {
		case ts := <-tsChan:
			fmt.Printf("Processing seed %d\n", ts)
			seed := ts
			for i := 0; i < KeySize; i++ {
				b, newSeed := prng(seed)
				seed = newSeed
				key[i] = byte(b & 0xff)
			}
			d, err := des.NewCipher(key)
			if err != nil {
				panic(err)
			}
			mode := cipher.NewCBCDecrypter(d, make([]byte, des.BlockSize))
			mode.CryptBlocks(buf, ciphertext)
			if bytes.HasPrefix(buf, []byte("%PDF-")) {
				fmt.Printf("Got it with epoch: %d", ts)
				ioutil.WriteFile(fmt.Sprintf("ElfUResearchLabsSuperSledOMaticQuickStartGuideV1.2-%d.pdf", ts), buf, 0644)
			}
		case <-done:
			return
		}
	}
}

func main() {
	ciphertext, err := ioutil.ReadFile("./ElfUResearchLabsSuperSledOMaticQuickStartGuideV1.2.pdf.enc")
	tsChan := make(chan int)
	doneChan := make(chan bool)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go worker(tsChan, doneChan, ciphertext)
	}
	startDate, err := time.Parse("Jan 2 15:04 MST 2006", "Dec 6 19:00 UTC 2019")
	if err != nil {
		panic(err)
	}
	startEpoch := startDate.Unix()
	endEpoch := startDate.Add(2 * time.Hour).Unix()
	for ts := startEpoch; ts < endEpoch; ts++ {
		tsChan <- int(ts)
	}
	for i := 0; i < 10; i++ {
		doneChan <- true
	}
	wg.Wait()
}
