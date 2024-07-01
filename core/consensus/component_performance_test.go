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

	//loads := []int{1, 40, 80, 120, 160, 200}
	loads := []int{1}

	data := make(map[int][]float64)
	for _, load := range loads {
		data[load] = testComponentPerformanceLatency(t, load)
	}

	// Store to file
	filename := "temp_cluster.json"
	path := "/home/diogo/dev/ist/thesis/graphs/data/"
	file, _ := os.Create(path + filename)
	defer file.Close()
	json.NewEncoder(file).Encode(data)
}

func testComponentPerformanceLatency(t *testing.T, load int) []float64 {
	t.Helper()

	const (
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

	// Metrics
	phasesDuration := make(map[string][]float64)

	// Run test N times to average results
	for it := 0; it < 5; it++ {

		ctx, cancel = context.WithCancel(context.Background())
		components = nil

		for i := 0; i < n; i++ {
			c, err := consensus.New(hosts[i], new(p2p.Sender), peers, p2pkeys[i], testDeadliner{}, func(core.Duty) bool { return true }, func(sci *pbv1.SniffedConsensusInstance) {}, abftShares[i+1], abftPublic, abftPubKeys)
			require.NoError(t, err)
			b := i
			c.Subscribe(func(_ context.Context, _ core.Duty, set core.UnsignedDataSet) error {
				core.RecordStep(int64(b), core.FINISH_CONSENSUS)
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
					core.RecordStep(int64(i), core.START_CONSENSUS)
					runErrs <- c.Propose(
						log.WithCtx(ctx, z.Int("node", i), z.Str("peer", p2p.PeerName(hosts[i].ID()))),
						core.Duty{Type: core.DutyAttester, Slot: uint64(l)},
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

				if count == n {
					break
				}
			}
			cancel() // Cancel to unblock Propose and record the time
		}
		core.RecordStep(0, core.FINISH_LOAD)
		cancel()

		// Sleep to give time for all RecordSteps to execute since some only happen after cancel()
		time.Sleep(100 * time.Millisecond)

		// Store to file (in case something goes wrong we wont lose all data)
		/*
			filename := "multisig_timestamps.json"
			path := "/home/diogo/dev/ist/thesis/graphs/data/"
			file, _ := os.Create(path + filename)
			defer file.Close()

			type pair struct {
				S string
				T int64
			}

			result := make([]pair, 0)

			for step, timestamps := range core.GetMetricsByPeer(0) {
				for _, timestamp := range timestamps {
					result = append(result, pair{step.String(), timestamp.UnixNano()})
				}
			}
			sort.Slice(result, func(i, j int) bool {
				return result[i].T < result[j].T
			})

			fmt.Println(result)

			json.NewEncoder(file).Encode(result)
		*/

		phasesDuration["load"] = append(phasesDuration["load"], core.ComputeAverageStep(core.START_LOAD, core.FINISH_LOAD, 1))

		// Record metrics per iteration
		core.ClearMetrics()
	}

	cancel()

	phases := []string{"load"}

	for _, phase := range phases {
		avg, std := core.ComputeAverageAndStandardDeviation(phasesDuration[phase])
		fmt.Printf("%s Duration\nAvg: %f\nStd: %f\n", phase, avg, std)
	}

	// Store to file (in case something goes wrong we wont lose all data)
	filename := "temp_cluster_qbft_" + fmt.Sprint(n) + ".json"
	path := "/home/diogo/dev/ist/thesis/graphs/data/"
	file, _ := os.Create(path + filename)
	defer file.Close()
	json.NewEncoder(file).Encode(phasesDuration["load"])

	return phasesDuration["load"]
}

func TestComponentPerformanceThroughput(t *testing.T) {
	// Consume metrics buffer
	go core.ConsumePerformanceBuffer()

	// From 256 bytes to 1MB
	sizes := []int{256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072}
	//sizes := []int{256}
	data := make(map[int][]float64)
	for _, size := range sizes {
		data[size] = testComponentPerformanceThroughput(t, size)
		fmt.Println(data)
	}

	// Store to file
	filename := "temp_throughput.json"
	path := "/home/diogo/dev/ist/thesis/graphs/data/"
	file, _ := os.Create(path + filename)
	defer file.Close()
	json.NewEncoder(file).Encode(data)
}

func testComponentPerformanceThroughput(t *testing.T, size int) (measurements []float64) {
	t.Helper()

	const (
		n    = 4
		f    = 1
		seed = 0
	)

	random := rand.New(rand.NewSource(0))
	lock, p2pkeys, _ := cluster.NewForT(t, 1, f+1, n, seed, random)
	pubkey := testutil.RandomCorePubKey(t)
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

	d := core.PayloadWithSize(size)

	for it := 0; it < 10; it++ {

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

		dutiesCompleted := 0
		running := true

		go func() {
			time.Sleep(3 * time.Second)
			running = false
		}()

		for ; running; dutiesCompleted++ {

			// Unblock propose
			ctx, cancel = context.WithCancel(context.Background())
			for i, c := range components {
				go func(ctx context.Context, i int, c *consensus.Component) {
					runErrs <- c.Propose(
						log.WithCtx(ctx, z.Int("node", i), z.Str("peer", p2p.PeerName(hosts[i].ID()))),
						core.Duty{Type: core.DutyTest, Slot: uint64(dutiesCompleted)},
						core.UnsignedDataSet{pubkey: d},
					)
				}(ctx, i, c)
			}

			var (
				count  int
				result core.UnsignedDataSet
			)
			for {
				select {
				case <-runErrs:
					// Issue:
					// When we cancel() the context, the propose function may return a consensus timeout errro
					// This is only consumed on the next iteration when dutionsCompleted = 0
					//if running && dutiesCompleted != 0 {
					//	testutil.RequireNoError(t, err)
					//}

				case res := <-results:
					//fmt.Println("res")
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

				if !running {
					break
				}
			}
			cancel()
		}
		measurements = append(measurements, float64(dutiesCompleted/3))
	}

	// Store to file (in case something goes wrong we wont lose all data)
	filename := "temp_throughput" + fmt.Sprint(size) + ".json"
	path := "/home/diogo/dev/ist/thesis/graphs/data/"
	file, _ := os.Create(path + filename)
	defer file.Close()
	json.NewEncoder(file).Encode(measurements)

	fmt.Println(measurements)

	return measurements
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

func TestComponentPerformanceCluster(t *testing.T) {

	// Consume metrics buffer
	go core.ConsumePerformanceBuffer()

	//faulty_nodes := []int{1}
	faulty_nodes := []int{4, 5, 6}

	data := make(map[int][]float64)
	for _, f := range faulty_nodes {
		data[f] = testComponentPerformanceCluster(t, f)
	}

	// Store to file
	filename := "temp_cluster.json"
	path := "/home/diogo/dev/ist/thesis/graphs/data/"
	file, _ := os.Create(path + filename)
	defer file.Close()
	json.NewEncoder(file).Encode(data)

	// Open file
	//filename := "temp_cluster.json"
	//path := "/home/diogo/dev/ist/thesis/graphs/data/"
	//file,_ :=  os.Open(path + filename)
	//var data2 map[int][]float64
	//json.NewDecoder(file).Decode(&data2)
	//fmt.Println(data2)
	//for k, v := range data {
	//	data2[k] = v
	//}
	//file.Close()
	//file, _ = os.Create(path + filename)
	//json.NewEncoder(file).Encode(data2)
	//fmt.Println(data2)

}

func testComponentPerformanceCluster(t *testing.T, f int) []float64 {
	t.Helper()

	const (
		seed = 0
	)

	var (
		n = 3*f + 1
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

	// Metrics
	phasesDuration := make(map[string][]float64)

	// Run test N times to average results
	for it := 0; it < 1; it++ {

		ctx, cancel = context.WithCancel(context.Background())
		components = nil

		for i := 0; i < n; i++ {
			c, err := consensus.New(hosts[i], new(p2p.Sender), peers, p2pkeys[i], testDeadliner{}, func(core.Duty) bool { return true }, func(sci *pbv1.SniffedConsensusInstance) {}, abftShares[i+1], abftPublic, abftPubKeys)
			require.NoError(t, err)
			b := i
			c.Subscribe(func(_ context.Context, _ core.Duty, set core.UnsignedDataSet) error {
				core.RecordStep(int64(b), core.FINISH_CONSENSUS)
				results <- set
				return nil
			})
			c.Start(log.WithCtx(ctx, z.Int("node", i)))

			components = append(components, c)
		}

		core.RecordStep(0, core.START_LOAD)

		// Propose values (blocking)
		for i, c := range components {
			go func(ctx context.Context, i int, c *consensus.Component) {
				core.RecordStep(int64(i), core.START_CONSENSUS)
				runErrs <- c.Propose(
					log.WithCtx(ctx, z.Int("node", i), z.Str("peer", p2p.PeerName(hosts[i].ID()))),
					core.Duty{Type: core.DutyAttester, Slot: uint64(0)},
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

			if count == n {
				break
			}
		}
		core.RecordStep(0, core.FINISH_LOAD)
		cancel()

		// Sleep to give time for all RecordSteps to execute since some only happen after cancel()
		time.Sleep(100 * time.Millisecond)

		phasesDuration["load"] = append(phasesDuration["load"], core.ComputeAverageStep(core.START_LOAD, core.FINISH_LOAD, 1))
		phasesDuration["consensus"] = append(phasesDuration["consensus"], core.ComputeAverageStep(core.START_CONSENSUS, core.FINISH_CONSENSUS, n))

		// Record metrics per iteration
		core.ClearMetrics()
	}

	cancel()

	phases := []string{"load", "consensus"}

	for _, phase := range phases {
		avg, std := core.ComputeAverageAndStandardDeviation(phasesDuration[phase])
		fmt.Printf("%s Duration\nAvg: %f\nStd: %f\n", phase, avg, std)
	}

	return phasesDuration["consensus"]
}
