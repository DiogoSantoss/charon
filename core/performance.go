package core

import (
	"math"
	"time"
)

type Step int

const (

	// Measure the time it takes for a given load (N duties)
	START_LOAD Step = iota
	FINISH_LOAD

	// Just considering local Propose to call to subscribers
	START_CONSENSUS
	FINISH_CONSENSUS

	// From c.Propose to just before alea.Run / qbft.Run
	START_SETUP
	FINISH_SETUP

	START_VCBC
	FINISH_VCBC

	START_VCBC_SEND
	FINISH_VCBC_SEND

	START_VERIFY_SIG
	FINISH_VERIFY_SIG

	START_VCBC_HANDLE_SEND
	FINISH_VCBC_HANDLE_SEND

	START_VCBC_HANDLE_READY
	FINISH_VCBC_HANDLE_READY

	START_VCBC_HANDLE_FINISH
	FINISH_VCBC_HANDLE_FINISH

	START_VCBC_SUBS
	FINISH_VCBC_SUBS

	START_VCBC_REQUEST
	FINISH_VCBC_REQUEST

	// Measure how long it takes for threshold number of VCBCs to finish
	// and start ABA
	START_DELAY_ABA
	FINISH_DELAY_ABA

	// Measure how long it takes for ABA to reach consensus
	START_ABA
	FINISH_ABA

	// Calling subscribers of the consensus
	START_DECIDE
	FINISH_DECIDE

	// QBFT
	START_QBFT_PREPREPARE_SEND
	FINISH_QBFT_PREPREPARE_SEND

	START_QBFT_HANDLE_PREPREPARE
	FINISH_QBFT_HANDLE_PREPREPARE

	START_QBFT_HANDLE_PREPARE
	FINISH_QBFT_HANDLE_PREPARE

	START_QBFT_HANDLE_COMMIT
	FINISH_QBFT_HANDLE_COMMIT

)

func (t Step) String() string {
	return typeLabels[t]
}

var typeLabels = map[Step]string{
	START_LOAD: "START_LOAD",
	FINISH_LOAD: "FINISH_LOAD",

	START_CONSENSUS: "START_CONSENSUS",
	FINISH_CONSENSUS: "FINISH_CONSENSUS",

	START_SETUP: "START_SETUP",
	FINISH_SETUP: "FINISH_SETUP",

	START_VCBC: "START_VCBC",
	FINISH_VCBC: "FINISH_VCBC",

	START_VCBC_SEND: "START_VCBC_SEND",
	FINISH_VCBC_SEND: "FINISH_VCBC_SEND",

	START_VERIFY_SIG: "START_VERIFY_SIG",
	FINISH_VERIFY_SIG: "FINISH_VERIFY_SIG",

	START_VCBC_HANDLE_SEND: "START_VCBC_HANDLE_SEND",
	FINISH_VCBC_HANDLE_SEND: "FINISH_VCBC_HANDLE_SEND",

	START_VCBC_HANDLE_READY: "START_VCBC_HANDLE_READY",
	FINISH_VCBC_HANDLE_READY: "FINISH_VCBC_HANDLE_READY",

	START_VCBC_HANDLE_FINISH: "START_VCBC_HANDLE_FINISH",
	FINISH_VCBC_HANDLE_FINISH: "FINISH_VCBC_HANDLE_FINISH",

	START_VCBC_SUBS: "START_VCBC_SUBS",
	FINISH_VCBC_SUBS: "FINISH_VCBC_SUBS",

	START_VCBC_REQUEST: "START_VCBC_REQUEST",
	FINISH_VCBC_REQUEST: "FINISH_VCBC_REQUEST",

	START_DELAY_ABA: "START_DELAY_ABA",
	FINISH_DELAY_ABA: "FINISH_DELAY_ABA",

	START_ABA: "START_ABA",
	FINISH_ABA: "FINISH_ABA",

	START_DECIDE: "START_DECIDE",
	FINISH_DECIDE: "FINISH_DECIDE",

	START_QBFT_PREPREPARE_SEND: "START_QBFT_PREPREPARE_SEND",
	FINISH_QBFT_PREPREPARE_SEND: "FINISH_QBFT_PREPREPARE_SEND",

	START_QBFT_HANDLE_PREPREPARE: "START_QBFT_HANDLE_PREPREPARE",
	FINISH_QBFT_HANDLE_PREPREPARE: "FINISH_QBFT_HANDLE_PREPREPARE",

	START_QBFT_HANDLE_PREPARE: "START_QBFT_HANDLE_PREPARE",
	FINISH_QBFT_HANDLE_PREPARE: "FINISH_QBFT_HANDLE_PREPARE",

	START_QBFT_HANDLE_COMMIT: "START_QBFT_HANDLE_COMMIT",
	FINISH_QBFT_HANDLE_COMMIT: "FINISH_QBFT_HANDLE_COMMIT",
}

type BufferEntry struct {
	peer int64
	step Step
	time time.Time
}

var (
	buffer  = make(chan BufferEntry, 100) // Avoid blocking to not affect performance
	metrics = make(map[int64]map[Step][]time.Time) // { peer0 -> {Step1: [t1,t2], Step2: [t1], ...}, peer1 -> ... }
)

func ConsumePerformanceBuffer() {
	for {
		e := <-buffer
		if metrics[e.peer] == nil {
			metrics[e.peer] = make(map[Step][]time.Time)
		}
		metrics[e.peer][e.step] = append(metrics[e.peer][e.step], e.time)
	}
}

func RecordStep(peerIdx int64, step Step) {
	buffer <- BufferEntry{
		peer: peerIdx,
		step: step,
		time: time.Now(),
	}
}

func ClearMetrics() {
	metrics = make(map[int64]map[Step][]time.Time)
}

func GetMetricsByPeerAndStep(step Step, peer int64) []time.Time {
	return metrics[peer][step]
}

func GetMetricsByPeer(peer int64) map[Step][]time.Time {
	return metrics[peer]
}

func ComputeAverage(values []float64) float64 {
	var avg float64 = 0
	for _, v := range values {
		avg += v
	}
	return avg / float64(len(values))
}

// Compute average between two steps.
// StepStart and StepFinish should match in the number of times that they are called.
// This ignores a step if one StepStart does not have a StepFinish matching.
// The simple case is for "single" step where start and finish are only called once.
// However some steps may be called multiple times and we also want to average that.
func ComputeAverageStep(stepStart, stepFinish Step, nodes int) (avg float64) {

	for _, metric := range metrics {

		start := metric[stepStart]
		finish := metric[stepFinish]
		length := int(math.Min(float64(len(start)), float64(len(finish))))

		if length == 0 {
			continue
		}
		// Average time within a given node (for steps that are called multiple times)
		var peerAvg float64 = 0
		for i := 0; i < length; i++ {
			elapsed := finish[i].Sub(start[i]).Milliseconds()
			peerAvg += float64(elapsed)
		}
		avg += peerAvg / float64(length)

	}
	// Average time for all nodes
	return avg / float64(nodes)
}

func ComputerAverageRepeatedStep(stepStart, stepFinish Step, nodes int) (avgs []float64) {
	arrByPeer := make([][]float64, 0)
	for _, metric := range metrics {
		start := metric[stepStart]
		finish := metric[stepFinish]
		length := int(math.Min(float64(len(start)), float64(len(finish))))
		if length == 0 {
			continue
		}

		peerAvg := make([]float64, 0)
		for i := 0; i < length; i++ {
			elapsed := finish[i].Sub(start[i]).Milliseconds()
			peerAvg = append(peerAvg, float64(elapsed))
		}
		arrByPeer = append(arrByPeer, peerAvg)
	}

	if len(arrByPeer) == 0 {
		return avgs
	}
	// Given the array containing array of times for each step (start to finish)
	// Compute the average across the first step from all peers, then the second step, and so on
	for i := 0; i < len(arrByPeer[0]); i++ {
		var avg float64 = 0
		for j := 0; j < len(arrByPeer); j++ {
			avg += arrByPeer[j][i]
		}
		avgs = append(avgs, avg/float64(len(arrByPeer)))
	}

	return avgs
}

func ComputeStandardDeviation(avg float64, values []float64) float64 {
	var (
		std float64
	)
	for i := 0; i < len(values); i++ {
		std += math.Pow(values[i]-avg, 2)
	}
	std = math.Sqrt(float64(std / float64(len(values))))
	return std
}

func ComputeAverageAndStandardDeviation(values []float64) (avg, std float64) {
	avg = ComputeAverage(values)
	std = ComputeStandardDeviation(avg, values)
	return avg, std
}
