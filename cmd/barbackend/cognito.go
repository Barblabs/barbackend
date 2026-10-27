package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"barbackend/internal/cognito"
	"github.com/aws/aws-sdk-go-v2/config"
)

type pool struct {
	region, id, clientID string
}

func cognitoPool() (pool, error) {
	p := pool{region: os.Getenv("COGNITO_REGION"), id: os.Getenv("COGNITO_USER_POOL_ID"), clientID: os.Getenv("COGNITO_CLIENT_ID")}
	if p.region == "" || p.id == "" {
		return pool{}, errors.New("COGNITO_REGION and COGNITO_USER_POOL_ID must be set")
	}
	return p, nil
}

func (p pool) verifier(ctx context.Context) (*cognito.Verifier, error) {
	if p.clientID == "" {
		return nil, errors.New("COGNITO_CLIENT_ID is not set")
	}
	issuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", p.region, p.id)
	return cognito.NewVerifier(ctx, cognito.VerifierConfig{
		Issuer:   issuer,
		ClientID: p.clientID,
		JWKSURL:  issuer + "/.well-known/jwks.json",
	})
}

func (p pool) admin(ctx context.Context) (*cognito.Admin, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(p.region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return cognito.NewAdmin(cfg, p.id), nil
}
