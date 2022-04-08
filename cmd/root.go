package cmd

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/celicoo/docli/v2"
	"github.com/ghodss/yaml"
	"github.com/thoas/go-funk"
	"log"
	"net/url"
	"os"
	"strings"
)

// Reference: https://github.com/celicoo/docli/blob/main/examples/git/cmd/clone.go
// Reference: https://github.com/k0kubun/pp

type IAMExtractor struct {
	RoleName             string
	SuppressOutputStdout bool
	FileName             string
}

// IamApi interface is used as the api interface for all functions that make AWS calls. This is so we can
// use dependency injection and mock out the AWS SDK for unit tests. See this AWS Documentation for reference:
// https://aws.github.io/aws-sdk-go-v2/docs/unit-testing/
type IamApi interface {
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
}

func (ie *IAMExtractor) Doc() string {
	return `usage: iam-extractor --role-name=<role name> --file-name=<output file name>

arguments:

	-r, --role-name					AWS IAM Role Name to extract
	-s, --suppress-output-stdout	Output the yaml fragment to stdout
	--file-name						The name of the file to write the output to. Optional.

`
}

func (ie *IAMExtractor) Run() {
	if ie.RoleName == "" {
		log.SetFlags(0) // removes the date/time from output.
		log.Fatalln("Role name is required. Please specify the --role-name argument.")
	}

	cfg, err := config.LoadDefaultConfig(context.TODO())

	if err != nil {
		log.Fatalf("Failed to load AWS configuration. %+v\n", err)
	}

	iamClient := iam.NewFromConfig(cfg)

	ie.extractIamRole(iamClient)
}

func (ie *IAMExtractor) Help() {
	fmt.Println(ie.Doc())
}

func (ie *IAMExtractor) Error(err error) {
	log.Fatalln(err)
}

func Execute() {
	var ie IAMExtractor
	args := docli.Args()
	args.Bind(&ie)
}

// getRole gets the IAM role basics and returns the aws iam api GetRoleOutput.
func (ie *IAMExtractor) getRole(iamClient IamApi) *iam.GetRoleOutput {
	roleOutput, err := iamClient.GetRole(context.TODO(), &iam.GetRoleInput{RoleName: aws.String(ie.RoleName)})

	if err != nil {
		log.Fatalf("Failed getting IAM role '%s' with error:\n%s", ie.RoleName, err.Error())
	}

	return roleOutput
}

// getInlinePolicies - gets the inline policies for the role and returns the aws iam client ListRolePoliciesOutput
func (ie *IAMExtractor) getInlinePolicies(iamClient IamApi) *iam.ListRolePoliciesOutput {
	roleInlinePoliciesOutput, err := iamClient.ListRolePolicies(context.TODO(), &iam.ListRolePoliciesInput{
		RoleName: aws.String(ie.RoleName),
	})

	if err != nil {
		log.Fatalf("Failed getting IAM role inline policies for role '%s' with error:\n%s", ie.RoleName, err.Error())
	}

	return roleInlinePoliciesOutput
}

// getManagedPolicies gets the managed policies from AWS and returns the iam api ListAttachedRolePoliciesOutput object.
func (ie *IAMExtractor) getManagedPolicies(iamClient IamApi) *iam.ListAttachedRolePoliciesOutput {
	roleManagedPoliciesOutput, err := iamClient.ListAttachedRolePolicies(context.TODO(), &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(ie.RoleName),
	})

	if err != nil {
		log.Fatalf("Failed getting IAM role managed policies for role '%s' with error:\n%s", ie.RoleName, err.Error())
	}

	return roleManagedPoliciesOutput
}

// getInlinePoliciesYaml gets the inline policies and shapes them into a yaml object. Each policy is a string in the slice.
func (ie *IAMExtractor) getInlinePoliciesYaml(iamClient IamApi, inlinePolicyNames []string) []string {
	// This funk.Map will enumerate each policy name and request the policy document for each.
	// It then returns a slice of the yaml representation of the policy documents.
	inlinePolicies := funk.Map(inlinePolicyNames, func(policyName string) string {
		rolePolicyOutput, _ := iamClient.GetRolePolicy(context.TODO(), &iam.GetRolePolicyInput{
			PolicyName: aws.String(policyName),
			RoleName:   aws.String(ie.RoleName),
		})

		pd, _ := url.QueryUnescape(*rolePolicyOutput.PolicyDocument)

		pdYaml, _ := yaml.JSONToYAML([]byte(pd))

		indented := indent(string(pdYaml), 10)

		yamlSegment := fmt.Sprintf("PolicyName: %s\n        PolicyDocument:\n%s", policyName, indented)

		return yamlSegment
	})

	return inlinePolicies.([]string)
}

// getSanitizedRoleName gets a role name that meets the requirements for a yaml object name.
func (ie *IAMExtractor) getSanitizedRoleName(unsanitizedRoleName string) string {
	sanitizedRoleName := strings.Replace(unsanitizedRoleName, "-", "", -1)

	return sanitizedRoleName
}

// getCfnYamlSnippet assembles the cloud formation snippet with proper indentation
func (ie *IAMExtractor) getCfnYamlSnippet(roleDescription string, yamlAssumedRolePolicyDoc string, maxSessionDuration int32, rolePath string, inlinePolicies []string, managedPolicyArns []string) string {
	sanitizedRoleName := ie.getSanitizedRoleName(ie.RoleName)

	cfn := fmt.Sprintf(`
%s:
  Type: AWS::IAM::Role
  Properties: 
    RoleName: %s
    Description: %s
    AssumeRolePolicyDocument:
%s
    MaxSessionDuration: %d
    Path: '%s'
    Policies:
      - %s
    ManagedPolicyArns:
    - %s
`, sanitizedRoleName,
		ie.RoleName, roleDescription,
		indent(yamlAssumedRolePolicyDoc, 6),
		maxSessionDuration, rolePath,
		strings.Join(inlinePolicies, "\n      - "),
		strings.Join(managedPolicyArns, "\n    - "))

	return cfn
}

// extractIamRole this function is the main entrypoint for extracting the role and handling stdio or file output.
func (ie *IAMExtractor) extractIamRole(iamClient IamApi) {
	roleOutput := ie.getRole(iamClient)

	roleInlinePoliciesOutput := ie.getInlinePolicies(iamClient)

	roleManagedPoliciesOutput := ie.getManagedPolicies(iamClient)

	inlinePolicies := ie.getInlinePoliciesYaml(iamClient, roleInlinePoliciesOutput.PolicyNames)

	managedPolicyArns := funk.Map(
		roleManagedPoliciesOutput.AttachedPolicies, func(policy types.AttachedPolicy) string {
			return *policy.PolicyArn
		})

	jsonAssumedRolePolicyDoc, _ := url.QueryUnescape(*roleOutput.Role.AssumeRolePolicyDocument)

	yamlAssumedRolePolicyDoc, _ := yaml.JSONToYAML([]byte(jsonAssumedRolePolicyDoc))

	cfn := ie.getCfnYamlSnippet(
		*roleOutput.Role.Description,
		string(yamlAssumedRolePolicyDoc),
		*roleOutput.Role.MaxSessionDuration,
		*roleOutput.Role.Path,
		inlinePolicies,
		managedPolicyArns.([]string))

	if !ie.SuppressOutputStdout {
		fmt.Println(cfn)
	}

	if ie.FileName != "" {
		os.WriteFile(ie.FileName, []byte(cfn), 0644)
	}
}

// indent separates string into lines, buffers the line with n spaces and then reassembles into string. (split/join)
func indent(s string, spaces int) string {
	spacer := strings.Repeat(" ", spaces)

	lines := strings.Split(s, "\n")

	lines = funk.Map(lines, func(line string) string {
		return fmt.Sprintf("%s%s", spacer, line)
	}).([]string)

	return strings.Join(lines, "\n")
}
