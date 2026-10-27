package cognito

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

// ErrUsernameExists is an email that already signs in to the user pool.
var ErrUsernameExists = errors.New("a user with this email already exists in cognito")

// Admin creates, disables and deletes users in one user pool, which signs users in by
// email.
type Admin struct {
	client *cip.Client
	poolID string
}

func NewAdmin(cfg aws.Config, poolID string) *Admin {
	return &Admin{client: cip.NewFromConfig(cfg), poolID: poolID}
}

// CreateUser creates the user and has Cognito email them an invitation with
// a temporary password. It returns the user's sub.
func (a *Admin) CreateUser(ctx context.Context, email string) (string, error) {
	out, err := a.client.AdminCreateUser(ctx, &cip.AdminCreateUserInput{
		UserPoolId: &a.poolID,
		Username:   &email,
		UserAttributes: []types.AttributeType{
			{Name: aws.String("email"), Value: &email},
			// Cognito sends password reset codes only to a verified email.
			{Name: aws.String("email_verified"), Value: aws.String("true")},
		},
		DesiredDeliveryMediums: []types.DeliveryMediumType{types.DeliveryMediumTypeEmail},
	})
	var exists *types.UsernameExistsException
	if errors.As(err, &exists) {
		return "", fmt.Errorf("create cognito user %s: %w", email, ErrUsernameExists)
	}
	if err != nil {
		return "", fmt.Errorf("create cognito user %s: %w", email, err)
	}
	for _, attr := range out.User.Attributes {
		if aws.ToString(attr.Name) == "sub" {
			return aws.ToString(attr.Value), nil
		}
	}
	return "", fmt.Errorf("create cognito user %s: response has no sub", email)
}

// DeleteUser accepts the sub because Cognito takes it wherever it takes a
// username.
func (a *Admin) DeleteUser(ctx context.Context, sub string) error {
	if _, err := a.client.AdminDeleteUser(ctx, &cip.AdminDeleteUserInput{UserPoolId: &a.poolID, Username: &sub}); err != nil {
		return fmt.Errorf("delete cognito user %s: %w", sub, err)
	}
	return nil
}

// DisableUser stops the user from signing in and revokes their access
// tokens.
func (a *Admin) DisableUser(ctx context.Context, sub string) error {
	if _, err := a.client.AdminDisableUser(ctx, &cip.AdminDisableUserInput{UserPoolId: &a.poolID, Username: &sub}); err != nil {
		return fmt.Errorf("disable cognito user %s: %w", sub, err)
	}
	return nil
}
