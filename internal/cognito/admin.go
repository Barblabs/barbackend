package cognito

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

// Admin creates users in one user pool, which signs users in by
// email.
type Admin struct {
	client *cip.Client
	poolID string
}

func NewAdmin(cfg aws.Config, poolID string) *Admin {
	return &Admin{client: cip.NewFromConfig(cfg), poolID: poolID}
}

// CreateUser has Cognito email the user an invitation with a temporary
// password, and returns their sub. It can be retried: when the pool has the
// email already, from an earlier attempt, it emails a new temporary
// password, or, when the user has set a password of their own, returns their
// sub as it is.
func (a *Admin) CreateUser(ctx context.Context, email string) (string, error) {
	sub, err := a.create(ctx, email)
	var exists *types.UsernameExistsException
	if !errors.As(err, &exists) {
		return sub, err
	}
	sub, err = a.resend(ctx, email)
	// Cognito resends only to a user who still has the temporary password.
	var passwordSet *types.UnsupportedUserStateException
	if !errors.As(err, &passwordSet) {
		return sub, err
	}
	return a.sub(ctx, email)
}

func (a *Admin) create(ctx context.Context, email string) (string, error) {
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
	if err != nil {
		return "", fmt.Errorf("create cognito user %s: %w", email, err)
	}
	return subAttribute(email, out.User.Attributes)
}

func (a *Admin) resend(ctx context.Context, email string) (string, error) {
	out, err := a.client.AdminCreateUser(ctx, &cip.AdminCreateUserInput{
		UserPoolId:             &a.poolID,
		Username:               &email,
		MessageAction:          types.MessageActionTypeResend,
		DesiredDeliveryMediums: []types.DeliveryMediumType{types.DeliveryMediumTypeEmail},
	})
	if err != nil {
		return "", fmt.Errorf("resend invitation to cognito user %s: %w", email, err)
	}
	return subAttribute(email, out.User.Attributes)
}

func (a *Admin) sub(ctx context.Context, email string) (string, error) {
	out, err := a.client.AdminGetUser(ctx, &cip.AdminGetUserInput{UserPoolId: &a.poolID, Username: &email})
	if err != nil {
		return "", fmt.Errorf("get cognito user %s: %w", email, err)
	}
	return subAttribute(email, out.UserAttributes)
}

func subAttribute(email string, attrs []types.AttributeType) (string, error) {
	for _, attr := range attrs {
		if aws.ToString(attr.Name) == "sub" {
			return aws.ToString(attr.Value), nil
		}
	}
	return "", fmt.Errorf("cognito user %s: response has no sub", email)
}
