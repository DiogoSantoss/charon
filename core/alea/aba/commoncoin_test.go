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
			Round:      0,
			StartDelay: nil,
			Slot:       0,
		})
	})

	t.Run("happy 1", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Round:      0,
			StartDelay: nil,
			Slot:       1,
		})
	})

	t.Run("stagger start", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Round: 0,
			StartDelay: map[int64]time.Duration{
				1: 1 * time.Second * 0,
				2: 1 * time.Second * 1,
				3: 1 * time.Second * 2,
				4: 1 * time.Second * 3,
			},
			Slot: 1,
		})
	})

	t.Run("one dead", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Round: 0,
			DeadNodes: map[int64]bool{
				1: true,
			},
			Slot: 1,
		})
	})

	t.Run("faulty signature", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Round: 0,
			StartDelay: map[int64]time.Duration{
				1: 1 * time.Second * 0,
				2: 1 * time.Second * 1,
				3: 1 * time.Second * 2,
				4: 1 * time.Second * 3,
			},
			FaultySig: map[int64]bool{
				1: true,
			},
			Slot: 1,
		})
	})
}

type testParametersCoin struct {
	Round      uint
	Slot       uint
	StartDelay map[int64]time.Duration
	DeadNodes  map[int64]bool
	FaultySig  map[int64]bool
}

func testCommonCoin(t *testing.T, test testParametersCoin) {

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
	resultChan := make(chan uint)
	resultsList := make([]uint, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	// Don't wait for processes that have faulty signatures
	// since they may never finish
	wg.Add(n - len(test.FaultySig))
	
	// Spawn go routines to participate in protocol
	for i := 0; i < n; i++ {

		id := i + 1

		go func(i int) {
			defer wg.Done()

			if test.StartDelay != nil {
				if delay, ok := test.StartDelay[int64(id)]; ok {
					time.Sleep(delay)
				}
			}

			if test.DeadNodes != nil {
				if _, ok := test.DeadNodes[int64(id)]; ok {
					t.Logf("node %d is dead", id)
					return
				}
			}

			if test.FaultySig != nil {
				if _, ok := test.FaultySig[int64(id)]; ok {
					t.Logf("node %d has faulty signature", id)
					secret, _ := tbls.GenerateSecretKey()
					shares[id] = secret
				}
			}

			result, err := SampleCoin(ctx, uint(id), test.Slot, test.Round, public, pubKeys, shares[id], broadcast, channels[i])
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
