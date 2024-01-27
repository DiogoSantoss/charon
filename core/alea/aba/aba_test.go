package aba

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/tbls"
)

func TestABA(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testABA(t, testParametersABA{
			Slot: 0,
			InputValue: map[uint]uint{
				1: 1,
				2: 1,
				3: 1,
				4: 1,
			},
			StartDelay: nil,
			DeadNodes:  nil,
		})
	})

	t.Run("happy 1", func(t *testing.T) {
		testABA(t, testParametersABA{
			Slot: 1,
			InputValue: map[uint]uint{
				1: 0,
				2: 0,
				3: 0,
				4: 0,
			},
			StartDelay: nil,
			DeadNodes:  nil,
		})
	})

	t.Run("different input", func(t *testing.T) {
		testABA(t, testParametersABA{
			Slot: 0,
			InputValue: map[uint]uint{
				1: 1,
				2: 0,
				3: 1,
				4: 0,
			},
			StartDelay: nil,
			DeadNodes:  nil,
		})
	})

	t.Run("stagger start", func(t *testing.T) {
		testABA(t, testParametersABA{
			Slot: 0,
			InputValue: map[uint]uint{
				1: 1,
				2: 1,
				3: 1,
				4: 1,
			},
			StartDelay: map[uint]time.Duration{
				1: 1 * time.Second * 0,
				2: 1 * time.Second * 1,
				3: 1 * time.Second * 2,
				4: 1 * time.Second * 3,
			},
			DeadNodes: nil,
		})
	})
}

type testParametersABA struct {
	Slot       uint
	InputValue map[uint]uint
	StartDelay map[uint]time.Duration
	DeadNodes  map[uint]bool
}

func testABA(t *testing.T, params testParametersABA) {

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

	// Resources for common coin
	commonCoinChannels := make([]chan CommonCoinMessage, n)
	commonCoinBroadcast := func(msg CommonCoinMessage) error {
		for _, channel := range commonCoinChannels {
			channel <- msg
		}
		return nil
	}

	// Resources for aba
	abaChannels := make([]chan ABAMessage, n)
	abaBroadcast := func(msg ABAMessage) error {
		for _, channel := range abaChannels {
			channel <- msg
		}
		return nil
	}

	// Create channels
	for i := 0; i < n; i++ {
		commonCoinChannels[i] = make(chan CommonCoinMessage, 1000)
		abaChannels[i] = make(chan ABAMessage, 1000)
	}

	// Store results
	resultChan := make(chan uint)
	resultsList := make([]uint, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(n)

	// Spawn go routines to participate in protocol
	for i := 0; i < n; i++ {

		id := i + 1

		go func(i int) {
			defer wg.Done()

			if params.StartDelay != nil {
				if delay, ok := params.StartDelay[uint(id)]; ok {
					time.Sleep(delay)
				}
			}

			result, err := RunABA(ctx, uint(id), params.Slot, public, pubKeys, shares[id], params.InputValue[uint(i)], abaBroadcast, abaChannels[i], commonCoinBroadcast, commonCoinChannels[i])
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
			close(commonCoinChannels[i])
			close(abaChannels[i])
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
