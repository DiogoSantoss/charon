package aba

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/tbls"
)

func TestCommonCoin(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Slot:  0,
			Tag:   0,
			Round: 0,
		})
	})

	t.Run("happy 1", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Slot:  1,
			Tag:   0,
			Round: 0,
		})
	})

	t.Run("stagger start", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Slot:  0,
			Tag:   0,
			Round: 0,
			StartDelay: map[uint]time.Duration{
				1: 1 * time.Second * 0,
				2: 1 * time.Second * 1,
				3: 1 * time.Second * 2,
				4: 1 * time.Second * 3,
			},
		})
	})

	t.Run("one dead", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Slot:  0,
			Tag:   0,
			Round: 0,
			DeadNodes: map[uint]bool{
				1: true,
			},
		})
	})

	t.Run("faulty signature", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Slot:  0,
			Tag:   0,
			Round: 0,
			StartDelay: map[uint]time.Duration{
				1: 1 * time.Second * 0,
				2: 1 * time.Second * 1,
				3: 1 * time.Second * 2,
				4: 1 * time.Second * 3,
			},
			FaultySig: map[uint]bool{
				1: true,
			},
		})
	})
}

type testParametersCoin struct {
	Slot       uint
	Tag        uint
	Round      uint
	StartDelay map[uint]time.Duration
	DeadNodes  map[uint]bool
	FaultySig  map[uint]bool
}

func testCommonCoin(t *testing.T, p testParametersCoin) {

	secret, _ := tbls.GenerateSecretKey()
	public, _ := tbls.SecretToPublicKey(secret)

	// Number of go routines and threshold size
	const f = 1
	const n = 3*f + 1

	// Generate private key shares and corresponding public keys
	shares, _ := tbls.ThresholdSplit(secret, n, f+1)
	pubKeys := make(map[uint]tbls.PublicKey)
	for i, share := range shares {
		pubKeys[uint(i)], _ = tbls.SecretToPublicKey(share)
	}

	channels := make([]chan CommonCoinMessage, n)
	broadcast := func(msg CommonCoinMessage) error {
		for _, channel := range channels {
			channel <- msg
		}
		return nil
	}

	// Create channels
	for i := 0; i < n; i++ {
		channels[i] = make(chan CommonCoinMessage, n)
	}

	// Store results
	resultChan := make(chan byte)
	resultsList := make([]byte, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	// Don't wait for processes that have faulty signatures
	// since they may never finish
	wg.Add(n - len(p.FaultySig))

	// Spawn go routines to participate in protocol
	for i := 0; i < n; i++ {

		id := i + 1

		go func(i int) {
			defer wg.Done()

			if p.StartDelay != nil {
				if delay, ok := p.StartDelay[uint(id)]; ok {
					time.Sleep(delay)
				}
			}

			if p.DeadNodes != nil {
				if _, ok := p.DeadNodes[uint(id)]; ok {
					t.Logf("node %d is dead", id)
					return
				}
			}

			if p.FaultySig != nil {
				if _, ok := p.FaultySig[uint(id)]; ok {
					t.Logf("node %d has faulty signature", id)
					secret, _ := tbls.GenerateSecretKey()
					shares[id] = secret
				}
			}

			c := NewCommonCoin(uint(id), p.Slot, p.Tag, p.Round, public, pubKeys, shares[id])

			result, err := c.SampleCoin(ctx, broadcast, channels[i])
			if err != nil {
				require.Failf(t, err.Error(), "aba execution %d failed", id)
			}
			resultChan <- result
		}(i)
	}

	go func() {
		wg.Wait()
		close(resultChan)
		for i := 0; i < n; i++ {
			close(channels[i])
		}
	}()

	for result := range resultChan {
		resultsList = append(resultsList, result)
	}

	require.Condition(t, func() (success bool) {

		if len(resultsList) <= 0 {
			return false
		}

		firstResult := resultsList[0]
		for _, res := range resultsList {
			if res != firstResult {
				return false
			}
		}

		return true
	})
}
