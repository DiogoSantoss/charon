package aba

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/core/alea/commoncoin"
	"github.com/obolnetwork/charon/tbls"
)

func TestABA(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testABA(t, testParametersABA{
			Instance:       0,
			AgreementRound: 0,
			InputValue: map[int64]byte{
				1: 1,
				2: 1,
				3: 1,
				4: 1,
			},
		})
	})

	t.Run("happy 1", func(t *testing.T) {
		testABA(t, testParametersABA{
			Instance:       1,
			AgreementRound: 1,
			InputValue: map[int64]byte{
				1: 0,
				2: 0,
				3: 0,
				4: 0,
			},
		})
	})

	t.Run("happy 2", func(t *testing.T) {
		testABA(t, testParametersABA{
			Instance:       1,
			AgreementRound: 2,
			InputValue: map[int64]byte{
				1: 1,
				2: 1,
				3: 1,
				4: 1,
			},
		})
	})

	t.Run("different input", func(t *testing.T) {
		testABA(t, testParametersABA{
			Instance:       0,
			AgreementRound: 0,
			InputValue: map[int64]byte{
				1: 1,
				2: 0,
				3: 1,
				4: 0,
			},
		})
	})

	t.Run("stagger start", func(t *testing.T) {
		testABA(t, testParametersABA{
			Instance:       0,
			AgreementRound: 0,
			InputValue: map[int64]byte{
				1: 1,
				2: 1,
				3: 1,
				4: 1,
			},
			StartDelay: map[int64]time.Duration{
				1: time.Second * 0,
				2: time.Second * 1,
				3: time.Second * 2,
				4: time.Second * 3,
			},
		})
	})

	t.Run("one dead", func(t *testing.T) {
		testABA(t, testParametersABA{
			Instance:       0,
			AgreementRound: 0,
			InputValue: map[int64]byte{
				1: 1,
				2: 1,
				3: 1,
				4: 1,
			},
			DeadNodes: map[int64]bool{
				1: true,
			},
		})
	})

	t.Run("faulty signature", func(t *testing.T) {
		testABA(t, testParametersABA{
			Instance:       0,
			AgreementRound: 0,
			InputValue: map[int64]byte{
				1: 1,
				2: 1,
				3: 1,
				4: 1,
			},
			StartDelay: map[int64]time.Duration{
				1: time.Second * 0,
				2: time.Second * 1,
				3: time.Second * 4,
				4: time.Second * 5,
			},
			FaultySig: map[int64]bool{
				1: true,
			},
		})
	})
}

type testParametersABA struct {
	Instance       int64
	AgreementRound int64
	InputValue     map[int64]byte
	StartDelay     map[int64]time.Duration
	DeadNodes      map[int64]bool
	FaultySig      map[int64]bool
}

func testABA(t *testing.T, params testParametersABA) {

	const (
		f = 1
		n = 3*f + 1
	)

	secret, _ := tbls.GenerateSecretKey()
	public, _ := tbls.SecretToPublicKey(secret)

	// Generate private key shares and corresponding public keys
	shares, _ := tbls.ThresholdSplit(secret, n, f+1)
	pubKeys := make(map[int64]tbls.PublicKey)
	for i, share := range shares {
		pubKeys[int64(i)], _ = tbls.SecretToPublicKey(share)
	}

	if params.FaultySig != nil {
		for k, v := range params.FaultySig {
			if v {
				t.Logf("node %d has faulty signature", k)
				secret, _ := tbls.GenerateSecretKey()
				shares[int(k)] = secret
			}
		}
	}

	// Create channels
	commonCoinChannels := make([]chan commoncoin.CommonCoinMsg[int64], n)
	abaChannels := make([]chan ABAMsg[int64], n)
	for i := 0; i < n; i++ {
		commonCoinChannels[i] = make(chan commoncoin.CommonCoinMsg[int64], 1000)
		abaChannels[i] = make(chan ABAMsg[int64], 1000)
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
			Broadcast: func(ctx context.Context, source int64, msgType MsgType,
				instance int64, agreementRound, round int64, estimative byte,
				values map[byte]struct{}) error {
				msg := msg{
					msgType:        msgType,
					source:         source,
					instance:       instance,
					agreementRound: agreementRound,
					round:          round,
					estimative:     estimative,
					values:         values,
				}

				for _, channel := range abaChannels {
					channel <- msg
				}
				return nil
			},
			Receive: abaChannels[i],
		}

		transCoin := commoncoin.Transport[int64]{
			Broadcast: func(ctx context.Context, source int64, instance int64, agreementRound, abaRound int64, sig tbls.Signature) error {
				msg := commonCoinMsg{
					source:         source,
					instance:       instance,
					agreementRound: agreementRound,
					abaRound:       abaRound,
					sig:            sig,
				}

				for _, channel := range commonCoinChannels {
					channel <- msg
				}
				return nil
			},
			Receive: commonCoinChannels[i],
			Refill:  commonCoinChannels[i],
		}

		defs := Definition{
			FastABA:   true,
			AsyncCoin: true,
			Nodes:     n,
		}

		getCommonCoinName := func(instance, agreementRound, abaRound int64) ([]byte, error) {
			name := fmt.Sprintf("AleaCommonCoin%v%v%v", instance, agreementRound, abaRound)
			nonce := sha256.Sum256([]byte(name))
			return nonce[:], nil
		}

		defsCoin := commoncoin.Definition[int64]{
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

			if params.StartDelay != nil {
				if delay, ok := params.StartDelay[int64(id)]; ok {
					time.Sleep(delay)
				}
			}

			if params.DeadNodes != nil {
				if _, ok := params.DeadNodes[int64(id)]; ok {
					t.Logf("node %d is dead", id)
					return
				}
			}

			result, err := Run(ctx, defs, trans, defsCoin, transCoin, params.Instance, int64(id), params.AgreementRound, params.InputValue[int64(id)])
			if err != nil {
				require.Failf(t, err.Error(), "aba execution %d failed", id)
			}
			resultChan <- result
		}(i)
	}

	go func() {
		wg.Wait()
		close(resultChan)
		commonCoinChannels = nil
		abaChannels = nil
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

type msg struct {
	msgType        MsgType
	source         int64
	instance       int64
	agreementRound int64
	round          int64
	estimative     byte
	values         map[byte]struct{}
}

func (m msg) MsgType() MsgType {
	return m.msgType
}

func (m msg) Source() int64 {
	return m.source
}

func (m msg) Instance() int64 {
	return m.instance
}

func (m msg) AgreementRound() int64 {
	return m.agreementRound
}

func (m msg) Round() int64 {
	return m.round
}

func (m msg) Estimative() byte {
	return m.estimative
}

func (m msg) Values() map[byte]struct{} {
	return m.values
}

func (m msg) CloneToInit() ABAMsg[int64] {
	values := make(map[byte]struct{})
	for k, v := range m.values {
		values[k] = v
	}
	return msg{
		msgType:        MsgInit,
		source:         m.source,
		instance:       m.instance,
		agreementRound: m.agreementRound,
		round:          m.round,
		estimative:     m.estimative,
		values:         values,
	}
}

type commonCoinMsg struct {
	source         int64
	instance       int64
	agreementRound int64
	abaRound       int64
	sig            tbls.Signature
}

func (m commonCoinMsg) Source() int64 {
	return m.source
}

func (m commonCoinMsg) Instance() int64 {
	return m.instance
}

func (m commonCoinMsg) AgreementRound() int64 {
	return m.agreementRound
}

func (m commonCoinMsg) AbaRound() int64 {
	return m.abaRound
}

func (m commonCoinMsg) Sig() tbls.Signature {
	return m.sig
}
