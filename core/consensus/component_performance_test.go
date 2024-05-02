package consensus_test

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/obolnetwork/charon/app/log"
	"github.com/obolnetwork/charon/app/z"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/core"
	"github.com/obolnetwork/charon/core/consensus"
	pbv1 "github.com/obolnetwork/charon/core/corepb/v1"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/testutil"
)

func TestComponentPerformance(t *testing.T) {

	/*
		Performance -> Latency/Throughput

		Latency -> Time taken to finish a single consensus instance

		Throughput -> Number of consensus instances finished in a given time

		Nodes -> 4 (f=1) and 7 (f=2)

	*/

	testComponentPerformanceLatency(t)
}

func testComponentPerformanceLatency(t *testing.T) {
	//t.Helper()

	threshold := 4
	nodes := 4

	seed := 0
	random := rand.New(rand.NewSource(int64(seed)))
	lock, p2pkeys, _ := cluster.NewForT(t, 1, threshold, nodes, seed, random)

	abftSecret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)
	abftPublic, err := tbls.SecretToPublicKey(abftSecret)
	require.NoError(t, err)
	abftFaulty := uint(math.Floor(float64(nodes-1) / 3))
	abftPubKeys := make(map[int64]tbls.PublicKey)
	abftShares, err := tbls.ThresholdSplit(abftSecret, uint(nodes), abftFaulty)
	require.NoError(t, err)
	for ii, share := range abftShares {
		abftPubKeys[int64(ii)], err = tbls.SecretToPublicKey(share)
		require.NoError(t, err)
	}

	var (
		peers       []p2p.Peer
		hosts       []host.Host
		hostsInfo   []peer.AddrInfo
		components  []*consensus.Component
		results     = make(chan core.UnsignedDataSet, threshold)
		runErrs     = make(chan error, threshold)
		ctx, cancel = context.WithCancel(context.Background())
	)
	defer cancel()

	// Create hosts and enrs (only for threshold).
	for i := 0; i < threshold; i++ {
		addr := testutil.AvailableAddr(t)
		mAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.IP, addr.Port))
		require.NoError(t, err)

		priv := (*libp2pcrypto.Secp256k1PrivateKey)(p2pkeys[i])
		h, err := libp2p.New(libp2p.Identity(priv), libp2p.ListenAddrs(mAddr))
		testutil.SkipIfBindErr(t, err)
		require.NoError(t, err)

		record, err := enr.Parse(lock.Operators[i].ENR)
		require.NoError(t, err)

		p, err := p2p.NewPeerFromENR(record, i)
		require.NoError(t, err)

		hostsInfo = append(hostsInfo, peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()})
		peers = append(peers, p)
		hosts = append(hosts, h)
	}

	// Connect each host with its peers
	for i := 0; i < threshold; i++ {
		for j := 0; j < threshold; j++ {
			if i == j {
				continue
			}
			err := hosts[i].Connect(ctx, hostsInfo[j])
			require.NoError(t, err)
		}
	}

	pubkey := testutil.RandomCorePubKey(t)

	var (
		times []int64
	)
	for it := 0; it < 100; it++ {

		ctx, cancel := context.WithCancel(context.Background())
		components = nil

		for i := 0; i < threshold; i++ {

			c, err := consensus.New(hosts[i], new(p2p.Sender), peers, p2pkeys[i], testDeadliner{}, func(core.Duty) bool { return true }, func(sci *pbv1.SniffedConsensusInstance) {}, abftShares[i+1], abftPublic, abftPubKeys)
			require.NoError(t, err)
			c.Subscribe(func(_ context.Context, _ core.Duty, set core.UnsignedDataSet) error {
				results <- set
				return nil
			})
			c.Start(log.WithCtx(ctx, z.Int("node", i)))

			components = append(components, c)
		}

		t0 := time.Now()

		for i, c := range components {
			go func(ctx context.Context, i int, c *consensus.Component) {
				runErrs <- c.Propose(
					log.WithCtx(ctx, z.Int("node", i), z.Str("peer", p2p.PeerName(hosts[i].ID()))),
					core.Duty{Type: core.DutyAttester, Slot: 1},
					core.UnsignedDataSet{pubkey: testutil.RandomCoreAttestationData(t)},
				)
			}(ctx, i, c)
		}

		var (
			count  int
			result core.UnsignedDataSet
		)
		for {
			select {
			case err := <-runErrs:
				testutil.RequireNoError(t, err)
			case res := <-results:
				t.Logf("Got result: %#v", res)
				if count == 0 {
					result = res
				} else {
					require.EqualValues(t, result, res)
				}
				count++
			}

			if count == threshold {
				duration := time.Since(t0).Milliseconds()
				times = append(times, duration)
				break
			}
		}

		cancel()
	}

	cancel()

	var (
		total int64   = 0
		avg   int64   = 0
		std   float64 = 0
	)
	for i, time := range times {
		total += time
		fmt.Printf("Iteration: %d\nTime: %dms\n\n", i, time)
	}
	avg = total / int64(len(times))
	fmt.Printf("Average: %dms\n", avg)

	for _, time := range times {
		std += math.Pow(float64(time-avg), 2)
	}
	std = math.Sqrt(float64(std / float64(len(times))))
	fmt.Printf("Standard Deviation: %f\n", std)

}
