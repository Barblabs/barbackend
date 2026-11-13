package main

import (
	"errors"
	"os"

	"barbackend/internal/slack"
)

func newSlackClient() (*slack.Client, error) {
	clientID := os.Getenv("SLACK_CLIENT_ID")
	clientSecret := os.Getenv("SLACK_CLIENT_SECRET")
	redirectURI := os.Getenv("SLACK_REDIRECT_URI")
	if clientID == "" || clientSecret == "" || redirectURI == "" {
		return nil, errors.New("SLACK_CLIENT_ID, SLACK_CLIENT_SECRET and SLACK_REDIRECT_URI must be set")
	}
	return slack.NewClient(slack.ClientConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
	}), nil
}
