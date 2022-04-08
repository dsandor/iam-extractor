/*
	There is very little code coverage with these tests. Need to add more tests.
*/
package cmd

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go/middleware"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

/*
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)

*/
type MockIamApi struct {
}

func (api *MockIamApi) GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	mockOutput := &iam.GetRoleOutput{
		Role: &types.Role{
			Arn:                      aws.String("fake-arn"),
			Path:                     aws.String("/"),
			RoleId:                   aws.String("0"),
			RoleName:                 aws.String("role-name"),
			AssumeRolePolicyDocument: aws.String("mock-policy-document"),
			Description:              aws.String("mock-description"),
			MaxSessionDuration:       aws.Int32(1),
		},
		ResultMetadata: middleware.Metadata{},
	}

	return mockOutput, nil
}

func (api *MockIamApi) GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	mockOutput := &iam.GetRolePolicyOutput{
		PolicyDocument: aws.String("mock-policy-doc"),
		PolicyName:     aws.String("policy-name"),
		RoleName:       aws.String("mock-role-name"),
		ResultMetadata: middleware.Metadata{},
	}

	return mockOutput, nil
}

func (api *MockIamApi) ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	mockOutput := &iam.ListRolePoliciesOutput{
		PolicyNames:    []string{"policy1", "policy2"},
		IsTruncated:    false,
		Marker:         nil,
		ResultMetadata: middleware.Metadata{},
	}

	return mockOutput, nil
}

func (api *MockIamApi) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	mockOutput := &iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: []types.AttachedPolicy{
			types.AttachedPolicy{
				PolicyArn:  aws.String("mock-policy-1-arn"),
				PolicyName: aws.String("mock-policy-1"),
			},
		},
		ResultMetadata: middleware.Metadata{},
	}

	return mockOutput, nil
}

func TestExtractIamRole(t *testing.T) {
	api := &MockIamApi{}
	ie := &IAMExtractor{
		RoleName:             "test-role-name",
		SuppressOutputStdout: true,
		FileName:             "",
	}

	output := ie.extractIamRole(api)

	assert.True(t, output != "", "CloudFormation snippet should not be empty string")
}

func TestRoleNameSanitized(t *testing.T) {
	api := &MockIamApi{}
	ie := &IAMExtractor{
		RoleName:             "test-role-name",
		SuppressOutputStdout: true,
		FileName:             "",
	}

	output := ie.extractIamRole(api)

	assert.True(t, strings.Contains(output, "testrolename:"))
	assert.True(t, strings.Contains(output, "RoleName: test-role-name:"))
}
