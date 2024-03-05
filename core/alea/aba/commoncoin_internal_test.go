package aba

import (
	"context"
	"testing"

	"github.com/obolnetwork/charon/tbls"
	"github.com/stretchr/testify/require"
)

func TestGetCommonCoinName(t *testing.T) {
	coinName, err := getCommonCoinName(0, 0, 0)
	require.NoError(t, err)
	require.NotEmpty(t, coinName)
}

func TestGetCommonCoinResult(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret, _ := tbls.GenerateSecretKey()
	public, _ := tbls.SecretToPublicKey(secret)
	shares, _ := tbls.ThresholdSplit(secret, 4, 2)

	signatures := map[int]tbls.Signature{}

	// wait for f+1 before revealing the coin
	for i := 0; i < 2; i++ {
		signature, err := getCommonCoinNameSigned(0, 0, 0, shares[i+1])
		require.NoError(t, err)
		signatures[i+1] = signature
	}

	result, err := getCommonCoinResult(ctx, 0, 0, 0, public, signatures)
	require.NoError(t, err)

	require.Condition(t, func() (success bool) {
		return result == 0 || result == 1
	})
}
