package vcbc

import (
	"context"
	"crypto/sha256"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/tbls"
)

func TestVCBC(t *testing.T) {
	t.Run("happy 0", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
			},
		})
	})
	t.Run("happy 1", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
				2: 2,
				3: 3,
				4: 4,
			},
		})
	})

	t.Run("stagger start", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
				2: 2,
				3: 3,
				4: 4,
			},
			StartDelay: map[int64]time.Duration{
				2: 1 * time.Second,
				3: 2 * time.Second,
				4: 3 * time.Second,
			},
		})
	})

	t.Run("one dead", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
				2: 2,
				3: 3,
				4: 4,
			},
			DeadNodes: map[int64]bool{
				2: true,
			},
		})
	})

	t.Run("faulty signature", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
				2: 2,
				3: 3,
				4: 4,
			},
			StartDelay: map[int64]time.Duration{
				2: 1 * time.Second,
				3: 2 * time.Second,
				4: 3 * time.Second,
			},
			FaultySig: map[int64]bool{
				1: true,
			},
		})
	})

	t.Run("happy req 0", func(t *testing.T) {
		testVCBC(t, testParametersVCBC{
			Instance: 0,
			InputValue: map[int64]int64{
				1: 1,
			},
			Requester: map[int64]bool{
				2: true,
			},
			StartDelay: map[int64]time.Duration{
				2: 1 * time.Second,
			},
		})
	})
}

type testParametersVCBC struct {
	Instance   int64
	InputValue map[int64]int64
	Requester  map[int64]bool
	StartDelay map[int64]time.Duration
	DeadNodes  map[int64]bool
	FaultySig  map[int64]bool
}

// Compute the total number of messages that should be received
func (t testParametersVCBC) totalNumberMessages() int {
	n := 0
	for _, v := range t.InputValue {
		if v != 0 {
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

	// Channels to communicate between go routines
	channels := make([]chan VCBCMessage[int64, int64], n)
	outputChannel := make(chan VCBCResult[int64], 1000)

	for i := 0; i < n; i++ {
		channels[i] = make(chan VCBCMessage[int64, int64], 1000)
	}

	ctx, cancel := context.WithCancel(context.Background())

	resultsList := make([]VCBCResult[int64], 0)

	var wg sync.WaitGroup
	wg.Add(n)

	// Spawn go routines to participate in protocol
	for i := 0; i < n; i++ {

		id := i + 1

		trans := Transport[int64, int64]{
			Broadcast: func(ctx context.Context, msg VCBCMessage[int64, int64]) error {
				for _, channel := range channels {
					// Don't send final to requester to simulate lack of final message
					if msg.Content.MsgType == MsgFinal && params.Requester != nil && params.Requester[int64(id)] {
						continue
					}
					channel <- msg
				}
				return nil
			},
			Unicast: func(ctx context.Context, target int64, msg VCBCMessage[int64, int64]) error {
				channels[target-1] <- msg
				return nil
			},
			Receive: channels[i],
		}

		hashFunction := sha256.New()
		defs := Definition[int64, int64]{
			BuildTag: func(instance int64, process int64) string {
				return "ID." + strconv.Itoa(int(process)) + "." + strconv.Itoa(int(instance))
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
			Subs: []func(context.Context, VCBCResult[int64]) error{func(ctx context.Context, result VCBCResult[int64]) error {
				outputChannel <- result
				return nil
			}},

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
				if isDead, ok := params.DeadNodes[int64(id)]; ok && isDead {
					t.Logf("node %d is dead", id)
					return
				}
			}

			if params.Requester != nil && params.Requester[int64(id)] {
				// Flush the message queue to pretend that he didn't receive any messages
				for len(channels[i]) != 0 {
					<-channels[i]
				}
				go func() {
					tag := defs.BuildTag(params.Instance, 1)
					err := BroadcastRequest(ctx, defs, trans, params.Instance, int64(id), tag)
					require.NoError(t, err)
				}()
			}

			err := Run(ctx, defs, trans, params.Instance, int64(id), params.InputValue[int64(id)])
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

		resultsByTag := make(map[string][]VCBCResult[int64])
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
				if firstResult.Result != result.Result {
					return false
				}
			}
		}

		return true
	})

}
