package aba

import (
	"context"
	"testing"

	"github.com/obolnetwork/charon/tbls"
	"github.com/stretchr/testify/require"
)

func TestGetCommonCoinName(t *testing.T) {
	c := NewCommonCoin(0, 0, 0, 0, tbls.PublicKey{}, map[uint]tbls.PublicKey{}, tbls.PrivateKey{})
	coinName, err := c.getCommonCoinName()
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
		c := NewCommonCoin(0, 0, 0, 0, public, map[uint]tbls.PublicKey{}, shares[i+1])
		signature, err := c.getCommonCoinNameSigned()
		require.NoError(t, err)
		signatures[i+1] = signature
	}

	c := NewCommonCoin(0, 0, 0, 0, public, map[uint]tbls.PublicKey{}, shares[0])
	result, err := c.getCommonCoinResult(ctx, signatures)
	require.NoError(t, err)

	require.Condition(t, func() (success bool) {
		return result == 0 || result == 1
	})
}
