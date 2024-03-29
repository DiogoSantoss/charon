package alea

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/core/alea/aba"
	"github.com/obolnetwork/charon/core/alea/commoncoin"
	"github.com/obolnetwork/charon/core/alea/vcbc"
	"github.com/obolnetwork/charon/tbls"
	"github.com/stretchr/testify/require"
)

func TestAlea(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
				2: 2,
				3: 3,
				4: 4,
			},
		})
	})

	t.Run("happy 1", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Instance: 1,
			InputValue: map[int64]int64{
				1: 5,
				2: 6,
				3: 7,
				4: 8,
			},
		})
	})

	t.Run("single 0", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Instance: 0,
			InputValue: map[int64]int64{
				3: 7,
			},
		})
	})

	t.Run("stagger start", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
				2: 2,
				3: 3,
				4: 4,
			},
			StartDelay: map[int64]time.Duration{
				1: 0,
				2: 1 * time.Second,
				3: 2 * time.Second,
				4: 3 * time.Second,
			},
		})
	})

	t.Run("one dead", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
				2: 2,
				3: 3,
				4: 4,
			},
			DeadNodes: map[int64]bool{
				1: true,
			},
		})
	})

	t.Run("faulty signature", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
				2: 2,
				3: 3,
				4: 4,
			},
			FaultySig: map[int64]bool{
				1: true,
			},
		})
	})

	t.Run("faulty signature and stagger start", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
				2: 2,
				3: 3,
				4: 4,
			},
			StartDelay: map[int64]time.Duration{
				1: 0,
				2: 1 * time.Second,
				3: 2 * time.Second,
				4: 2 * time.Second, //if this is 3s then a lot of ABA rounds will pass and fill channel buffer
			},
			FaultySig: map[int64]bool{
				1: true,
			},
		})
	})
}

type testParametersAlea struct {
	Instance   int64
	InputValue map[int64]int64
	StartDelay map[int64]time.Duration
	DeadNodes  map[int64]bool
	FaultySig  map[int64]bool
}

// Compute the total number of messages that should be received
func (t testParametersAlea) totalNumberMessages() int {
	n := 4
	for _, v := range t.DeadNodes {
		if v {
			n--
		}
	}
	// Faulty signatures will not decrease the number of messages
	// since there are enough good signatures to threshold aggregate

	return n
}

func testAlea(t *testing.T, p testParametersAlea) {

	const (
		f = 1
		n = 3*f + 1
	)
	var (
		decided bool = false
	)

	secret, _ := tbls.GenerateSecretKey()
	public, _ := tbls.SecretToPublicKey(secret)

	// Generate private key shares and corresponding public keys
	shares, _ := tbls.ThresholdSplit(secret, n, f+1)
	pubKeys := make(map[int64]tbls.PublicKey)
	for i, share := range shares {
		pubKeys[int64(i)], _ = tbls.SecretToPublicKey(share)
	}

	if p.FaultySig != nil {
		for k, v := range p.FaultySig {
			if v {
				t.Logf("node %d has faulty signature", k)
				secret, _ := tbls.GenerateSecretKey()
				shares[int(k)] = secret
			}
		}
	}

	// Channels for VCBC/ABA/CommonCoin

	vcbcChannels := make([]chan vcbc.VCBCMessage[int64], n)
	abaChannels := make([]chan aba.ABAMessage[int64], n)
	commonCoinChannels := make([]chan commoncoin.CommonCoinMessage[int64], n)

	for i := 0; i < n; i++ {
		vcbcChannels[i] = make(chan vcbc.VCBCMessage[int64], 1000)
		abaChannels[i] = make(chan aba.ABAMessage[int64], 1000)
		commonCoinChannels[i] = make(chan commoncoin.CommonCoinMessage[int64], 1000)
	}

	// Channel for Alea result
	outputChannel := make(chan int64, n)

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(n)

	// Spawn go routines to participate in protocol
	for i := 0; i < n; i++ {

		id := i + 1

		defs := Definition[int64, int64]{
			GetLeader: func(instance, agreementRound int64) int64 {
				return (instance+agreementRound)%int64(n) + 1
			},
			SignData: func(data []byte) (tbls.Signature, error) {
				return tbls.Sign(shares[id], data)
			},
			Decide: func(ctx context.Context, instance, result int64) {
				outputChannel <- result
			},
			Nodes: n,
		}

		transABA := aba.Transport[int64]{
			Broadcast: func(ctx context.Context, msg aba.ABAMessage[int64]) error {
				for _, channel := range abaChannels {
					if channel != nil {
						channel <- msg
					}
				}
				return nil
			},
			Receive: abaChannels[i],
		}

		defsABA := aba.Definition{
			Nodes: n,
		}

		getCommonCoinName := func(instance, agreementRound, abaRound int64) ([]byte, error) {
			name := fmt.Sprintf("AleaCommonCoin%v%v%v", instance, agreementRound, abaRound)
			nonce := sha256.Sum256([]byte(name))
			return nonce[:], nil
		}

		transCoin := commoncoin.Transport[int64]{
			Broadcast: func(ctx context.Context, msg commoncoin.CommonCoinMessage[int64]) error {
				for _, channel := range commonCoinChannels {
					if channel != nil {
						channel <- msg
					}
				}
				return nil
			},
			Receive: commonCoinChannels[i],
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

		transVCBC := vcbc.Transport[int64]{
			Broadcast: func(ctx context.Context, msg vcbc.VCBCMessage[int64]) error {
				for _, channel := range vcbcChannels {
					if channel != nil {
						channel <- msg
					}
				}
				return nil
			},
			Unicast: func(ctx context.Context, target int64, msg vcbc.VCBCMessage[int64]) error {
				vcbcChannels[target-1] <- msg
				return nil
			},
			Receive: vcbcChannels[i],
		}

		hashFunction := sha256.New()
		defsVCBC := vcbc.Definition[int64, int64]{
			BuildTag: func(instance int64, process int64) string {
				return "ID." + strconv.Itoa(int(process)) + "." + strconv.Itoa(int(instance))
			},
			SlotFromTag: func(tag string) int64 {
				slot, _ := strconv.Atoi(strings.Split(tag, ".")[2])
				return int64(slot)
			},
			IdFromTag: func(tag string) int64 {
				id, _ := strconv.Atoi(strings.Split(tag, ".")[1])
				return int64(id)
			},
			HashValue: func(value int64) []byte {
				hashFunction.Write([]byte(strconv.FormatInt(value, 10)))
				hash := hashFunction.Sum(nil)
				hashFunction.Reset()
				return hash
			},
			SignData: func(data []byte) (tbls.Signature, error) {
				return tbls.Sign(shares[id], data)
			},
			VerifySignature: func(process int64, data []byte, signature tbls.Signature) error {
				return tbls.Verify(pubKeys[int64(process)], data, signature)
			},
			VerifyAggregateSignature: func(data []byte, signature tbls.Signature) error {
				return tbls.Verify(public, data, signature)
			},
			// Missing output as it is defined inside Alea
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

			valueChannel := make(chan int64, 1)
			valueChannel <- p.InputValue[int64(id)]

			err := Run(ctx, defs, defsVCBC, transVCBC, defsABA, transABA, defsCoin, transCoin, p.Instance, int64(id), valueChannel)
			if !decided {
				require.NoError(t, err)
			}
			close(valueChannel)
		}(i)
	}

	// Close channels when all done
	go func() {
		wg.Wait()
		for i := 0; i < n; i++ {
			close(vcbcChannels[i])
			close(abaChannels[i])
			close(commonCoinChannels[i])
		}
	}()

	resultList := make([]int64, 0)

	// Collect results, stop when received N results
	for result := range outputChannel {
		resultList = append(resultList, result)
		if len(resultList) == p.totalNumberMessages() {
			decided = true
			break
		}
	}
	cancel()

	require.Condition(t, func() (success bool) {
		if len(resultList) <= 0 {
			return false
		}

		firstResult := resultList[0]
		for _, result := range resultList {
			if result != firstResult {
				return false
			}
		}
		return true
	})
}
