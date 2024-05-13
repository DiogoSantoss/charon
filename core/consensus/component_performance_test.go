package consensus_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
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

// Create BLS keys necessary for AleaBFT protocol
func createBLSKeys(t *testing.T, n, f uint) (tbls.PublicKey, tbls.PrivateKey, map[int64]tbls.PublicKey, map[int]tbls.PrivateKey) {
	abftSecret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)
	abftPublic, err := tbls.SecretToPublicKey(abftSecret)
	require.NoError(t, err)

	abftPubKeys := make(map[int64]tbls.PublicKey)
	abftShares, err := tbls.ThresholdSplit(abftSecret, n, f+1)
	require.NoError(t, err)

	for ii, share := range abftShares {
		abftPubKeys[int64(ii)], err = tbls.SecretToPublicKey(share)
		require.NoError(t, err)
	}
	return abftPublic, abftSecret, abftPubKeys, abftShares
}

func TestComponentPerformanceLatency(t *testing.T) {

	// Consume metrics buffer
	go core.ConsumePerformanceBuffer()

	// Destination file
	filename := "test.json"
	path := "/home/diogo/dev/ist/thesis/graphs/data/"
	loads := []int{1, 10}

	data := make(map[int][]float64)
	for _, load := range loads {
		data[load] = testComponentPerformanceLatency(t, load)
	}

	file, _ := os.Create(path + filename)
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.Encode(data)
}

func testComponentPerformanceLatency(t *testing.T, load int) []float64 {
	t.Helper()

	var (
		n    = 4
		f    = 1
		seed = 0
	)

	random := rand.New(rand.NewSource(0))
	lock, p2pkeys, _ := cluster.NewForT(t, 1, f+1, n, seed, random)
	abftPublic, _, abftPubKeys, abftShares := createBLSKeys(t, uint(n), uint(f))

	var (
		peers       []p2p.Peer
		hosts       []host.Host
		hostsInfo   []peer.AddrInfo
		components  []*consensus.Component
		results     = make(chan core.UnsignedDataSet, n)
		runErrs     = make(chan error, n)
		ctx, cancel = context.WithCancel(context.Background())
	)
	defer cancel()

	for i := 0; i < n; i++ {
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
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			err := hosts[i].Connect(ctx, hostsInfo[j])
			require.NoError(t, err)
		}
	}

	pubkey := testutil.RandomCorePubKey(t)

	var (
		loadDuration      = make([]float64, 0)
		proposeDuration   = make([]float64, 0)
		setupDuration     = make([]float64, 0)
		consensusDuration = make([]float64, 0)
		vcbcDuration      = make([]float64, 0)
		abaDuration       = make([]float64, 0)
		abaRoundDuration  = make([]float64, 0)
		coinDuration      = make([]float64, 0)
	)

	// Run the test N times to average the results
	for it := 0; it < 5; it++ {

		ctx, cancel = context.WithCancel(context.Background())
		components = nil

		for i := 0; i < n; i++ {
			c, err := consensus.New(hosts[i], new(p2p.Sender), peers, p2pkeys[i], testDeadliner{}, func(core.Duty) bool { return true }, func(sci *pbv1.SniffedConsensusInstance) {}, abftShares[i+1], abftPublic, abftPubKeys)
			require.NoError(t, err)
			c.Subscribe(func(_ context.Context, _ core.Duty, set core.UnsignedDataSet) error {
				results <- set
				return nil
			})
			c.Start(log.WithCtx(ctx, z.Int("node", i)))

			components = append(components, c)
		}

		core.RecordStep(0, core.START_LOAD)
		for l := 0; l < load; l++ {
			ctx, cancel = context.WithCancel(context.Background())
			// Propose values (blocking)
			for i, c := range components {
				go func(ctx context.Context, i int, c *consensus.Component) {
					core.RecordStep(int64(i), core.START_PROPOSE)
					runErrs <- c.Propose(
						log.WithCtx(ctx, z.Int("node", i), z.Str("peer", p2p.PeerName(hosts[i].ID()))),
						core.Duty{Type: core.DutyAttester, Slot: uint64(l)},
						core.UnsignedDataSet{pubkey: testutil.RandomCoreAttestationData(t)},
					)
					core.RecordStep(int64(i), core.FINISH_PROPOSE)
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
					if count == 0 {
						result = res
					} else {
						require.EqualValues(t, result, res)
					}
					count++
				}

				if count == n {
					break
				}
			}
			cancel() // Cancel to unblock Propose and record the time
		}
		cancel()
		core.RecordStep(0, core.FINISH_LOAD)
		// Sleep to give time for all RecordSteps to execute since some only happen after cancel()
		time.Sleep(100 * time.Millisecond)
		loadDuration = append(loadDuration, core.ComputeAverageStep(core.START_LOAD, core.FINISH_LOAD, 1))
		proposeDuration = append(proposeDuration, core.ComputeAverageStep(core.START_PROPOSE, core.FINISH_PROPOSE, n))
		setupDuration = append(setupDuration, core.ComputeAverageStep(core.START_SETUP, core.FINISH_SETUP, n))
		consensusDuration = append(consensusDuration, core.ComputeAverageStep(core.START_CONSENSUS, core.FINISH_CONSENSUS, n))
		vcbcDuration = append(vcbcDuration, core.ComputeAverageStep(core.START_VCBC, core.FINISH_VCBC, n))
		abaDuration = append(abaDuration, core.ComputeAverageStep(core.START_ABA, core.FINISH_ABA, n))
		abaRoundDuration = append(abaRoundDuration, core.ComputeAverageStep(core.START_ABA_ROUND, core.FINISH_ABA_ROUND, n))
		coinDuration = append(coinDuration, core.ComputeAverageStep(core.START_COIN, core.FINISH_COIN, n))

		fmt.Println("ABA round durations:")
		fmt.Println(core.ComputerAverageRepeatedStep(core.START_ABA_ROUND, core.FINISH_ABA_ROUND, n))

		// Record metrics per iteration
		core.ClearMetrics()
	}

	cancel()

	avg, std := core.ComputeAverageAndStandardDeviation(loadDuration)
	fmt.Printf("Load Duration\nAvg: %f\nStd: %f\n", avg, std)
	avg, std = core.ComputeAverageAndStandardDeviation(proposeDuration)
	fmt.Printf("Propose Duration\nAvg: %f\nStd: %f\n", avg, std)
	avg, std = core.ComputeAverageAndStandardDeviation(setupDuration)
	fmt.Printf("Setup Duration\nAvg: %f\nStd: %f\n", avg, std)
	avg, std = core.ComputeAverageAndStandardDeviation(consensusDuration)
	fmt.Printf("Consensus Duration\nAvg: %f\nStd: %f\n", avg, std)
	avg, std = core.ComputeAverageAndStandardDeviation(vcbcDuration)
	fmt.Printf("VCBC Duration\nAvg: %f\nStd: %f\n", avg, std)
	avg, std = core.ComputeAverageAndStandardDeviation(abaDuration)
	fmt.Printf("ABA Duration\nAvg: %f\nStd: %f\n", avg, std)
	avg, std = core.ComputeAverageAndStandardDeviation(abaRoundDuration)
	fmt.Printf("ABA Round Duration\nAvg: %f\nStd: %f\n", avg, std)
	avg, std = core.ComputeAverageAndStandardDeviation(coinDuration)
	fmt.Printf("Coin Duration\nAvg: %f\nStd: %f\n", avg, std)

	return loadDuration
}

func TestComponentPerformanceThroughput(t *testing.T) {
	t.Helper()

	var (
		n    = 4
		f    = 1
		seed = 0
	)

	random := rand.New(rand.NewSource(0))
	lock, p2pkeys, _ := cluster.NewForT(t, 1, f+1, n, seed, random)
	abftPublic, _, abftPubKeys, abftShares := createBLSKeys(t, uint(n), uint(f))

	var (
		peers       []p2p.Peer
		hosts       []host.Host
		hostsInfo   []peer.AddrInfo
		components  []*consensus.Component
		results     = make(chan core.UnsignedDataSet, n)
		runErrs     = make(chan error, n)
		ctx, cancel = context.WithCancel(context.Background())
	)
	defer cancel()

	for i := 0; i < n; i++ {
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

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			err := hosts[i].Connect(ctx, hostsInfo[j])
			require.NoError(t, err)
		}
	}

	pubkey := testutil.RandomCorePubKey(t)

	go core.ConsumePerformanceBuffer()

	ctx, cancel = context.WithCancel(context.Background())

	for i := 0; i < n; i++ {
		c, err := consensus.New(hosts[i], new(p2p.Sender), peers, p2pkeys[i], testDeadliner{}, func(core.Duty) bool { return true }, func(sci *pbv1.SniffedConsensusInstance) {}, abftShares[i+1], abftPublic, abftPubKeys)
		require.NoError(t, err)
		c.Subscribe(func(_ context.Context, _ core.Duty, set core.UnsignedDataSet) error {
			results <- set
			return nil
		})
		c.Start(log.WithCtx(ctx, z.Int("node", i)))

		components = append(components, c)
	}

	var (
		duration        time.Duration = 3
		it              int
		reachedDeadline bool = false
	)
	go func() {
		time.Sleep(duration * time.Second)
		reachedDeadline = true
		cancel()
	}()
	for it = 0; !reachedDeadline; it++ {

		// Propose values (blocking)
		for i, c := range components {
			go func(ctx context.Context, i int, c *consensus.Component) {
				runErrs <- c.Propose(
					log.WithCtx(ctx, z.Int("node", i), z.Str("peer", p2p.PeerName(hosts[i].ID()))),
					core.Duty{Type: core.DutyAttester, Slot: uint64(it)},
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
				if !reachedDeadline {
					testutil.RequireNoError(t, err)
				}
			case res := <-results:
				if count == 0 {
					result = res
				} else {
					require.EqualValues(t, result, res)
				}
				count++
			}

			if count == n {
				break
			}
			if reachedDeadline {
				break
			}
		}
	}

	// TODO: why -2
	fmt.Printf("Duration: %ds\nDuties Agreed: %d\nThroughput: %d duties/s\n", duration, it-2, (it-2)/int(duration))
}

func TestComponentPerformanceCrash(t *testing.T) {
	t.Helper()

	var (
		n    = 4
		f    = 1
		seed = 0
	)

	random := rand.New(rand.NewSource(0))
	lock, p2pkeys, _ := cluster.NewForT(t, 1, f+1, n, seed, random)
	abftPublic, _, abftPubKeys, abftShares := createBLSKeys(t, uint(n), uint(f))

	var (
		peers       []p2p.Peer
		hosts       []host.Host
		hostsInfo   []peer.AddrInfo
		components  []*consensus.Component
		results     = make(chan core.UnsignedDataSet, n)
		runErrs     = make(chan error, n)
		ctx, cancel = context.WithCancel(context.Background())
	)
	defer cancel()

	for i := 0; i < n; i++ {
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

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			err := hosts[i].Connect(ctx, hostsInfo[j])
			require.NoError(t, err)
		}
	}

	pubkey := testutil.RandomCorePubKey(t)

	go core.ConsumePerformanceBuffer()

	ctx, cancel = context.WithCancel(context.Background())

	for i := 0; i < n; i++ {
		c, err := consensus.New(hosts[i], new(p2p.Sender), peers, p2pkeys[i], testDeadliner{}, func(core.Duty) bool { return true }, func(sci *pbv1.SniffedConsensusInstance) {}, abftShares[i+1], abftPublic, abftPubKeys)
		require.NoError(t, err)
		c.Subscribe(func(_ context.Context, _ core.Duty, set core.UnsignedDataSet) error {
			results <- set
			return nil
		})
		c.Start(log.WithCtx(ctx, z.Int("node", i)))
		components = append(components, c)

	}

	// Propose values (blocking)
	for i, c := range components {
		if i == 0 {
			continue
		}
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
			if count == 0 {
				result = res
			} else {
				require.EqualValues(t, result, res)
			}
			count++
		}

		if count == n-1 {
			break
		}
	}
	cancel()
}
