package vcbc

import (
	"context"
	"math"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/tbls"
)

func TestVCBC(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
			Slot: 0,
			InputValue: map[uint][]byte{
				1: []byte("Hello World!"),
				2: nil,
				3: nil,
				4: nil,
			},
		})
	})
	t.Run("happy 1", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
			Slot: 0,
			InputValue: map[uint][]byte{
				1: []byte("Hello"),
				2: []byte("World"),
				3: []byte("Goodbye"),
				4: []byte("Planet"),
			},
		})
	})

	t.Run("stagged start", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
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
		})
	})

	t.Run("one dead", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
			Slot: 0,
			InputValue: map[uint][]byte{
				1: []byte("Hello"),
				2: []byte("World"),
				3: []byte("Goodbye"),
				4: []byte("Planet"),
			},
			DeadNodes: map[uint]bool{
				1: false,
				2: true,
				3: false,
				4: false,
			},
		})
	})

	t.Run("faulty signature", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
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
			FaultySig: map[uint]bool{
				1: true,
			},
		})
	})

	t.Run("happy req 0", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
			Slot: 0,
			InputValue: map[uint][]byte{
				1: []byte("Hello World!"),
				2: nil,
				3: nil,
				4: nil,
			},
			Requester: map[uint]bool{
				1: false,
				2: true,
				3: false,
				4: false,
			},
			StartDelay: map[uint]time.Duration{
				1: 0,
				2: 1 * time.Second,
				3: 0,
				4: 0,
			},
		})
	})
}

type testParametersVCBC struct {
	Slot       uint
	InputValue map[uint][]byte
	Requester  map[uint]bool
	StartDelay map[uint]time.Duration
	DeadNodes  map[uint]bool
	FaultySig  map[uint]bool
}

// Compute the total number of messages that should be received
func (t testParametersVCBC) totalNumberMessages() int {
	n := 0
	for _, v := range t.InputValue {
		if v != nil {
			n++
		}
	}
	for _, v := range t.Requester {
		if v {
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

	return int(math.Pow(float64(n), 2))
}

func testVCBC(t *testing.T, params testParametersVCBC) {

	const (
		f = 1
		n = 3*f + 1
	)
	var (
		receivedAll bool = false
	)

	secret, _ := tbls.GenerateSecretKey()
	public, _ := tbls.SecretToPublicKey(secret)

	// Generate private key shares and corresponding public keys
	shares, _ := tbls.ThresholdSplit(secret, n, f+1)
	pubKeys := make(map[uint]tbls.PublicKey)
	for i, share := range shares {
		pubKeys[uint(i)], _ = tbls.SecretToPublicKey(share)
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

	// Channels to communicate between go routines
	channels := make([]chan VCBCMessage, n)
	outputChannel := make(chan VCBCResult, 1000)

	for i := 0; i < n; i++ {
		channels[i] = make(chan VCBCMessage, 1000)
	}

	// Functions to send messages
	broadcast := func(msg VCBCMessage) error {
		for i, channel := range channels {
			// Don't send final to requester to simulate lack of final message
			if msg.Content.MsgType == MsgFinal && params.Requester != nil && params.Requester[uint(i+1)] {
				continue
			}
			channel <- msg
		}
		return nil
	}
	unicast := func(id uint, msg VCBCMessage) error {
		channels[id-1] <- msg
		return nil
	}

	resultsList := make([]VCBCResult, 0)
	ctx, cancel := context.WithCancel(context.Background())

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

			if params.DeadNodes != nil {
				if isDead, ok := params.DeadNodes[uint(id)]; ok && isDead {
					t.Logf("node %d is dead", id)
					return
				}
			}

			v := NewVCBC(n, f, uint(id), params.Slot, public, pubKeys, shares[id])
			v.Subscribe(func(ctx context.Context, result VCBCResult) error {
				outputChannel <- result
				return nil
			})

			if params.Requester != nil && params.Requester[uint(id)] {
				go func() {
					tag := BuildTag(uint(1), params.Slot)
					err := v.BroadcastRequest(ctx, tag, broadcast)
					require.NoError(t, err)
				}()
			}

			err := v.Run(ctx, params.InputValue[uint(id)], broadcast, unicast, channels[i])
			if !receivedAll {
				require.NoError(t, err)
			}

		}(i)
	}

	go func() {
		wg.Wait()
		for i := 0; i < n; i++ {
			close(channels[i])
		}
		close(outputChannel)
	}()

	for result := range outputChannel {
		resultsList = append(resultsList, result)
		// Cancel context when all messages are received
		// "all messages" is a value computed from the input parameters
		if len(resultsList) == params.totalNumberMessages() {
			receivedAll = true
			break
		}
	}
	cancel()

	require.Condition(t, func() (success bool) {
		if len(resultsList) <= 0 {
			return false
		}

		resultsByTag := make(map[string][]VCBCResult)
		for _, result := range resultsList {
			resultsByTag[result.Tag] = append(resultsByTag[result.Tag], result)
		}

		// For each tag, all messages should be the same
		for tag := range resultsByTag {
			if len(resultsByTag[tag]) == 0 {
				break
			}
			firstResult := resultsByTag[tag][0]
			for _, result := range resultsByTag[tag] {
				if !slices.Equal(firstResult.Message, result.Message) {
					return false
				}
			}
		}

		return true
	})

}
