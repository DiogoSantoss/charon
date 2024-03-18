package commoncoin

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/tbls"
)

func TestCommonCoin(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Instance:       0,
			AgreementRound: 0,
			AbaRound:       0,
		})
	})

	t.Run("happy 1", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Instance:       1,
			AgreementRound: 1,
			AbaRound:       1,
		})
	})

	t.Run("stagger start", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Instance:       0,
			AgreementRound: 0,
			AbaRound:       0,
			StartDelay: map[int64]time.Duration{
				1: 1 * time.Second * 0,
				2: 1 * time.Second * 1,
				3: 1 * time.Second * 2,
				4: 1 * time.Second * 3,
			},
		})
	})

	t.Run("one dead", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Instance:       0,
			AgreementRound: 0,
			AbaRound:       0,
			DeadNodes: map[int64]bool{
				1: true,
			},
		})
	})

	t.Run("faulty signature", func(t *testing.T) {
		testCommonCoin(t, testParametersCoin{
			Instance:       0,
			AgreementRound: 0,
			AbaRound:       0,
			StartDelay: map[int64]time.Duration{
				1: 1 * time.Second * 0,
				2: 1 * time.Second * 1,
				3: 1 * time.Second * 2,
				4: 1 * time.Second * 3,
			},
			FaultySig: map[int64]bool{
				1: true,
			},
		})
	})
}

type testParametersCoin struct {
	Instance       int64
	AgreementRound int64
	AbaRound       int64
	StartDelay     map[int64]time.Duration
	DeadNodes      map[int64]bool
	FaultySig      map[int64]bool
}

func testCommonCoin(t *testing.T, p testParametersCoin) {

	// Number of go routines and threshold size
	const (
		f = 1
		n = 3*f +1
	)

	secret, _ := tbls.GenerateSecretKey()
	public, _ := tbls.SecretToPublicKey(secret)

	// Generate private key shares and corresponding public keys
	shares, _ := tbls.ThresholdSplit(secret, n, f+1)
	pubKeys := make(map[int64]tbls.PublicKey)
	for i, share := range shares {
		pubKeys[int64(i)], _ = tbls.SecretToPublicKey(share)
	}

	// Channels for communication
	channels := make([]chan CommonCoinMessage[int64], n)
	for i := 0; i < n; i++ {
		channels[i] = make(chan CommonCoinMessage[int64], n)
	}

	// Store results
	resultChan := make(chan byte)
	resultsList := make([]byte, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(n)

	// Spawn go routines to participate in protocol
	for i := 0; i < n; i++ {

		id := i + 1

		trans := Transport[int64]{
			Broadcast: func(ctx context.Context, msg CommonCoinMessage[int64]) error {
				for _, channel := range channels {
					channel <- msg
				}
				return nil
			},
			Receive: channels[i],
		}

		getCommonCoinName := func(instance, agreementRound, abaRound int64) ([]byte, error) {
			name := fmt.Sprintf("AleaCommonCoin%v%v%v", instance, agreementRound, abaRound)
			nonce := sha256.Sum256([]byte(name))
			return nonce[:], nil
		}

		defs := Definition[int64]{
			GetCommonCoinName: getCommonCoinName,
			GetCommonCoinNameSigned: func(instance, agreementRound, abaRound int64) (tbls.Signature, error) {
				name, err := getCommonCoinName(instance, agreementRound, abaRound)
				if err != nil {
					return tbls.Signature{}, err
				}
				return tbls.Sign(shares[id], name)
			},
			GetCommonCoinResult: func(ctx context.Context, instance, agreementRound, abaRound int64, signatures map[int]tbls.Signature) (byte, error) {
				totalSig, err := tbls.ThresholdAggregate(signatures)
				if err != nil {
					return 0, err
				}

				sid, err := getCommonCoinName(instance, agreementRound, abaRound)
				if err != nil {
					return 0, err
				}

				err = tbls.Verify(public, sid, totalSig)
				if err != nil {
					log.Info(ctx, "Failed to verify aggregate signature")
					return 0, err
				}

				return totalSig[0] & 1, nil
			},
			VerifySignature: func(process int64, data []byte, signature tbls.Signature) error {
				return tbls.Verify(pubKeys[int64(process)], data, signature)
			},
			Nodes: n,
		}

		go func(i int) {
			defer wg.Done()

			if p.StartDelay != nil {
				if delay, ok := p.StartDelay[int64(id)]; ok {
					time.Sleep(delay)
				}
			}

			if p.DeadNodes != nil {
				if _, ok := p.DeadNodes[int64(id)]; ok {
					t.Logf("node %d is dead", id)
					return
				}
			}

			if p.FaultySig != nil {
				if _, ok := p.FaultySig[int64(id)]; ok {
					t.Logf("node %d has faulty signature", id)
					secret, _ := tbls.GenerateSecretKey()
					shares[id] = secret
				}
			}

			result, err := SampleCoin(ctx, defs, trans, p.Instance, p.AgreementRound, p.AbaRound, int64(id))
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
