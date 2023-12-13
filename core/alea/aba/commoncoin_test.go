package aba

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/tbls"
)

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
	channels := make([]chan TempABAMessage, n)

	// send message to all channels
	broadcast := func(id int, signature tbls.Signature) error {
		for _, channel := range channels {
			channel <- TempABAMessage{id, signature}
		}
		return nil
	}

	// store results
	resultChan := make(chan uint)
	resultsList := make([]uint, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	// spawn go routines to participate in protocol
	for i := 0; i < n; i++ {

		id := i + 1
		slot, round := 0, 0
		channels[i] = make(chan TempABAMessage, n)

		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			result, err := SampleCoin(ctx, id, slot, round, shares[id], broadcast, channels[i])
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
		} else {
			return false
		}

		return true
	})
}
