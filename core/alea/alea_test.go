package alea

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/obolnetwork/charon/core/alea/aba"
	"github.com/obolnetwork/charon/core/alea/vcbc"
	"github.com/obolnetwork/charon/tbls"
	"github.com/stretchr/testify/require"
)

func TestAlea(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Slot: 0,
			InputValue: map[uint][]byte{
				1: []byte("Hello"),
				2: []byte("World"),
				3: []byte("Goodbye"),
				4: []byte("Planet"),
			},
			StartDelay: nil,
			DeadNodes:  nil,
			FaultySig:  nil,
		})
	})

	t.Run("happy 1", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Slot: 1,
			InputValue: map[uint][]byte{
				1: []byte("abdagadg"),
				2: []byte("fwesgweg"),
				3: []byte("reag"),
				4: []byte("h4rger"),
			},
			StartDelay: nil,
			DeadNodes:  nil,
			FaultySig:  nil,
		})
	})

	t.Run("stagged start", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Slot: 0,
			InputValue: map[uint][]byte{
				1: []byte("Hello"),
				2: []byte("World"),
				3: []byte("Goodbye"),
				4: []byte("Planet"),
			},
			StartDelay: map[uint]time.Duration{
				1: 0,
				2: 1 * time.Second,
				3: 2 * time.Second,
				4: 3 * time.Second,
			},
			DeadNodes: nil,
			FaultySig: nil,
		})
	})

	t.Run("one dead", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Slot: 0,
			InputValue: map[uint][]byte{
				1: []byte("Hello"),
				2: []byte("World"),
				3: []byte("Goodbye"),
				4: []byte("Planet"),
			},
			StartDelay: nil,
			DeadNodes: map[uint]bool{
				1: true,
			},
			FaultySig: nil,
		})
	})

	t.Run("faulty signature", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Slot: 0,
			InputValue: map[uint][]byte{
				1: []byte("Hello"),
				2: []byte("World"),
				3: []byte("Goodbye"),
				4: []byte("Planet"),
			},
			StartDelay: nil,
			DeadNodes:  nil,
			FaultySig:  map[uint]bool{
				1: true,
			},
		})
	})

	t.Run("faulty signature and stagger start", func(t *testing.T) {
		testAlea(t, testParametersAlea{
			Slot: 0,
			InputValue: map[uint][]byte{
				1: []byte("Hello"),
				2: []byte("World"),
				3: []byte("Goodbye"),
				4: []byte("Planet"),
			},
			StartDelay: map[uint]time.Duration{
				1: 0,
				2: 1 * time.Second,
				3: 2 * time.Second,
				4: 2 * time.Second, //if this is 3s then a lot of ABA rounds will pass and fill channel buffer
			},
			DeadNodes:  nil,
			FaultySig:  map[uint]bool{
				1: true,
			},
		})
	})
}

type testParametersAlea struct {
	Slot uint
	InputValue map[uint][]byte
	StartDelay map[uint]time.Duration
	DeadNodes map[uint]bool
	FaultySig map[uint]bool
}

// Compute the total number of messages that should be received
func (t testParametersAlea) totalNumberMessages() int {
	n := 0
	for _, v := range t.InputValue {
		if v != nil {
			n++
		}
	}
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
	pubKeys := make(map[uint]tbls.PublicKey)
	for i, share := range shares {
		pubKeys[uint(i)], _ = tbls.SecretToPublicKey(share)
	}

	if p.FaultySig != nil {
		for k,v := range p.FaultySig {
			if v {
				t.Logf("node %d has faulty signature", k)
				secret, _ := tbls.GenerateSecretKey()
				shares[int(k)] = secret
			}
		}
	}

	// Channels for VCBC/ABA/CommonCoin

	vcbcChannels := make([]chan vcbc.VCBCMessage, n)
	abaChannels := make([]chan aba.ABAMessage, n)
	commonCoinChannels := make([]chan aba.CommonCoinMessage, n)

	for i := 0; i < n; i++ {
		vcbcChannels[i] = make(chan vcbc.VCBCMessage, 1000)
		abaChannels[i] = make(chan aba.ABAMessage, 1000)
		commonCoinChannels[i] = make(chan aba.CommonCoinMessage, 1000)
	}

	// Channel for Alea result

	outputChannel := make(chan []byte, n)

	// Functions to send messages

	broadcastVCBC := func(msg vcbc.VCBCMessage) error {
		for _, channel := range vcbcChannels {
			channel <- msg
		}
		return nil
	}

	unicastVCBC := func(id uint, msg vcbc.VCBCMessage) error {
		vcbcChannels[id-1] <- msg
		return nil
	}

	broadcastABA := func(msg aba.ABAMessage) error {
		for _, channel := range abaChannels {
			channel <- msg
		}
		return nil
	}

	broadcastCommonCoin := func(msg aba.CommonCoinMessage) error {
		for _, channel := range commonCoinChannels {
			channel <- msg
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(n)

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

			valueChannel := make(chan []byte, 1)
			valueChannel <- []byte("test")

			a := NewAlea(n, f)

			a.Subscribe(func(ctx context.Context, result []byte) error {
				outputChannel <- result
				return nil
			})

			err := a.Run(ctx, uint(id), 1, valueChannel, public, pubKeys, shares[id], broadcastABA, abaChannels[i], broadcastCommonCoin, commonCoinChannels[i], broadcastVCBC, unicastVCBC, vcbcChannels[i])
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

	resultList := make([][]byte, 0)

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
			if string(result) != string(firstResult) {
				return false
			}
		}
		return true
	})
}
