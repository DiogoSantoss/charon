package aba

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/tbls"
)

func TestABA(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testABA(t, parametersABA{})
	})
}

// TODO: better name that does not clash with commocoin_test struct
type parametersABA struct {

}

func testABA(t *testing.T, params parametersABA) {

	secret, _ := tbls.GenerateSecretKey()
	public, _ := tbls.SecretToPublicKey(secret)

	// Number of go routines and threshold size
	const f = 1
	const n = 3*f + 1

	// generate private key shares and corresponding public keys
	shares, _ := tbls.ThresholdSplit(secret, n, f+1)
	pubKeys := make(map[uint]tbls.PublicKey)
	for i, share := range shares {
		pubKeys[uint(i)], _ = tbls.SecretToPublicKey(share)
	}

	// Resources for common coin
	commonCoinChannels := make([]chan CommonCoinMessage, n)
	commonCoinBroadcast := func (msg CommonCoinMessage) error {
		for _, channel := range commonCoinChannels {
			channel <- msg
		}
		return nil
	}

	// Resources for aba
	abaChannels := make([]chan ABAMessage, n)
	abaBroadcast := func (msg ABAMessage) error {
		for _, channel := range abaChannels {
			channel <- msg
		}
		return nil
	}

	// store results
	resultChan := make(chan uint)
	resultsList := make([]uint, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(n)
	
	// spawn go routines to participate in protocol
	for i := 0; i < n; i++ {

		commonCoinChannels[i] = make(chan CommonCoinMessage, 1000)
		abaChannels[i] = make(chan ABAMessage, 1000)

		go func(i int) {
			defer wg.Done()

			result, err := RunABA(ctx, uint(i+1), 0, public, pubKeys, shares[i+1], 1, abaBroadcast, abaChannels[i], commonCoinBroadcast, commonCoinChannels[i])
			if err != nil {
				require.Failf(t, err.Error(), "aba execution %d failed", i+1)
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

		if len(resultsList) > 0 {
			firstResult := resultsList[0]
			for _, res := range resultsList {
				if res != firstResult {
					return false
				}
			}
		} else {
			return false
		}

		return true
	})
}
