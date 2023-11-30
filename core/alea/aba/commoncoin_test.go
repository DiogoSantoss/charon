package aba_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/core/alea/aba"
	"github.com/obolnetwork/charon/tbls"
)

func TestGetCommonCoinName(t *testing.T) {
	coinName, err := aba.GetCommonCoinName(0, 0)
	require.NoError(t, err)
	require.NotEmpty(t, coinName)
}

func TestGetCommonCoinResult(t *testing.T) {
	coinName := []byte("AleaCommmonCoin00")

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	shares, err := tbls.ThresholdSplit(secret, 4, 2)
	require.NoError(t, err)

	signatures := map[int]tbls.Signature{}

	// wait for f+1 before revealing the coin
	for i := 0; i < 2; i++ {
		signature, err := tbls.Sign(shares[i+1], coinName)
		require.NoError(t, err)
		signatures[i+1] = signature
	}

	totalSig, err := tbls.ThresholdAggregate(signatures)
	require.NoError(t, err)

	result := uint(totalSig[0] & 1)
	require.Condition(t, func() (success bool) {
		return result == 0 || result == 1
	})
}

func TestRun(t *testing.T) {
	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	// Number of go routines and threshold size
	const f = 1
	const n = 3*f + 1

	shares, err := tbls.ThresholdSplit(secret, n, f+1)
	require.NoError(t, err)

	// set of channels for communication
	channels := make([]chan aba.TempABAMessage, n)

	// send message to all channels
	broadcast := func(id int, signature tbls.Signature) error {
		for _, channel := range channels {
			channel <- aba.TempABAMessage{id, signature}
		}
		return nil
	}

	// store results
	resultChan := make(chan uint)
	resultsList := make([]uint, 0)

	var wg sync.WaitGroup
	// spawn go routines to participate in protocol
	for i := 0; i < n; i++ {

		id := i + 1
		slot, round := 0, 0
		channels[i] = make(chan aba.TempABAMessage, n)

		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			result, err := aba.Run(id, slot, round, shares[id], broadcast, channels[i])
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

		if len(resultsList) > 0 {
			firstResult := resultsList[0]
			for _, res := range resultsList {
				if res != firstResult {
					return false
				}
			}
		}

		return true
	})
}
