package aba

import (
	"testing"

	"github.com/obolnetwork/charon/tbls"
	"github.com/stretchr/testify/require"
)

func TestGetCommonCoinName(t *testing.T) {
	coinName, err := getCommonCoinName(0, 0)
	require.NoError(t, err)
	require.NotEmpty(t, coinName)
}

func TestGetCommonCoinResult(t *testing.T) {
	coinName,_ := getCommonCoinName(0,0)

	secret, err := tbls.GenerateSecretKey()
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	shares, err := tbls.ThresholdSplit(secret, 4, 2)
	require.NoError(t, err)

	signatures := map[int]tbls.Signature{}

	// wait for f+1 before revealing the coin
	for i := 0; i < 2; i++ {
		signature, err := tbls.Sign(shares[i+1], coinName)
		require.NoError(t, err)
		signatures[i+1] = signature
	}

	totalSig, err := tbls.ThresholdAggregate(signatures)
	require.NoError(t, err)

	result := uint(totalSig[0] & 1)
	require.Condition(t, func() (success bool) {
		return result == 0 || result == 1
	})
}
