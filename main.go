package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type PolicyInfo struct {
	PolicyArn  *string
	PolicyName *string
	Path       *string
	VersionId  *string
	UserName   *string
	Document   *string
}

func main() {
	mode := flag.String("mode", "resource", "Must be one of: resource") // TODO other stuff: actions, etc.
	flag.Parse()
	if flag.NArg() != 2 {
		panic("must supply arguments: <action> <resource>")
	}
	action := flag.Arg(0)
	resource := flag.Arg(1)

	// Load the Shared AWS Configuration (~/.aws/config)
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	iamClient := iam.NewFromConfig(cfg)

	if *mode == "resource" {
		searchResource(context.Background(), iamClient, action, resource)
	}
}

func searchResource(ctx context.Context, iamClient *iam.Client, action string, resource string) {
	policies := make(chan *types.Policy)
	go func() {
		defer close(policies)
		var marker *string
		for {
			policyList, err := iamClient.ListPolicies(ctx, &iam.ListPoliciesInput{
				// TODO expose more flags
				Scope:  types.PolicyScopeTypeLocal, // TODO expose, default to customer-managed only
				Marker: marker,
			})
			if err != nil {
				fmt.Printf("error listing policies: %s", err.Error())
				break
			}

			for _, p := range policyList.Policies {
				policies <- &p
			}
			if policyList.IsTruncated {
				marker = policyList.Marker
			} else {
				break
			}
		}
	}()

	policyVersions := make(chan *struct {
		Policy  *types.Policy
		Version *types.PolicyVersion
	})
	go func() {
		defer close(policyVersions)
		for policy := range policies {
			var marker *string
			for {
				out, err := iamClient.ListPolicyVersions(ctx, &iam.ListPolicyVersionsInput{
					PolicyArn: policy.Arn,
					Marker:    marker,
				})
				if err != nil {
					fmt.Printf("error listing policy versions: %s", err.Error())
					break
				}

				for _, version := range out.Versions {
					policyVersions <- &struct {
						Policy  *types.Policy
						Version *types.PolicyVersion
					}{
						Policy:  policy,
						Version: &version,
					}
				}
				if out.IsTruncated {
					marker = out.Marker
				} else {
					break
				}
			}
		}
	}()

	policyDocuments := make(chan *PolicyInfo)
	go func() {
		defer close(policyDocuments)
		for policyVersion := range policyVersions {
			out, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: policyVersion.Policy.Arn,
				VersionId: policyVersion.Version.VersionId,
			})
			if err != nil {
				fmt.Printf("error getting policy version: %s", err.Error())
				break
			}
			doc, err := url.QueryUnescape(*out.PolicyVersion.Document)
			if err != nil {
				fmt.Printf("%s %s error=unable to decode policy document %s", *policyVersion.Policy.Arn, *policyVersion.Version.VersionId, err.Error())
				break
			}
			policyDocuments <- &PolicyInfo{
				PolicyArn:  policyVersion.Policy.Arn,
				PolicyName: policyVersion.Policy.PolicyName,
				Path:       policyVersion.Policy.Path,
				VersionId:  out.PolicyVersion.VersionId,
				Document:   &doc,
			}
		}
	}()

	users := make(chan types.User)
	go func() {
		defer close(users)
		var marker *string
		for {
			out, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{
				Marker: marker,
			})
			if err != nil {
				fmt.Printf("error listing users: %s\n", err.Error())
				break
			}
			for _, user := range out.Users {
				users <- user
			}
			if out.IsTruncated {
				marker = out.Marker
			} else {
				break
			}
		}
	}()

	userPolicies := make(chan *struct {
		UserName       *string
		UserPolicyName *string
	})
	go func() {
		defer close(userPolicies)
		for user := range users {
			var marker *string
			for {
				out, err := iamClient.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
					UserName: user.UserName,
					Marker:   marker,
				})
				if err != nil {
					fmt.Printf("error listing user policies: %s", err.Error())
					break
				}
				for _, it := range out.PolicyNames {
					userPolicies <- &struct {
						UserName       *string
						UserPolicyName *string
					}{
						UserName:       user.UserName,
						UserPolicyName: &it,
					}
				}
				if out.IsTruncated {
					marker = out.Marker
				} else {
					break
				}
			}
		}
	}()

	go func() {
		for userPolicy := range userPolicies {
			out, err := iamClient.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
				PolicyName: userPolicy.UserPolicyName,
				UserName:   userPolicy.UserName,
			})
			if err != nil {
				fmt.Printf("error getting user policy: %s\n", err.Error())
				break
			}
			doc, err := url.QueryUnescape(*out.PolicyDocument)
			if err != nil {
				fmt.Printf("%s %s error=unable to decode user policy document %s", *userPolicy.UserName, *userPolicy.UserPolicyName, err.Error())
				break
			}
			policyDocuments <- &PolicyInfo{
				PolicyName: out.PolicyName,
				UserName:   out.UserName,
				Document:   &doc,
			}
		}
	}()

	fmt.Printf("The action %s on the resource %s is allowed by the following policies:\n", action, resource)
	for policyDocument := range policyDocuments {
		out, err := iamClient.SimulateCustomPolicy(ctx, &iam.SimulateCustomPolicyInput{
			ActionNames:     []string{action},
			ResourceArns:    []string{resource},
			PolicyInputList: []string{*policyDocument.Document},
		})

		if err == nil && out.EvaluationResults[0].EvalDecision != types.PolicyEvaluationDecisionTypeAllowed {
			continue
		}

		if policyDocument.PolicyArn == nil {
			// user inline policy
			fmt.Printf("(user inline policy) UserName=%s PolicyName=%s", *policyDocument.UserName, *policyDocument.PolicyName)
			if err != nil {
				fmt.Printf(" error=%s", err.Error())
			}
			fmt.Println()
		} else {
			// managed policy
			fmt.Printf("Arn=%s VersionId=%s", *policyDocument.PolicyArn, *policyDocument.VersionId)
			if err != nil {
				fmt.Printf(" error=%s", err.Error())
			}
			fmt.Println()

			var marker *string
			for {
				out2, err := iamClient.ListEntitiesForPolicy(ctx, &iam.ListEntitiesForPolicyInput{
					PolicyArn: policyDocument.PolicyArn,
					Marker:    marker,
				})
				if err != nil {
					fmt.Printf("error trying to list entities for policy %s: %s", *policyDocument.PolicyArn, err.Error())
					break
				}
				for _, group := range out2.PolicyGroups {
					fmt.Printf("\tis attached to group: Name=%s Id=%s\n", *group.GroupName, *group.GroupId)
				}
				for _, role := range out2.PolicyRoles {
					fmt.Printf("\tis attached to role: Name=%s Id=%s\n", *role.RoleName, *role.RoleId)
				}
				for _, user := range out2.PolicyUsers {
					fmt.Printf("\tis attached to user: Name=%s Id=%s\n", *user.UserName, *user.UserId)
				}
				if out2.IsTruncated {
					marker = out2.Marker
				} else {
					break
				}
			}
		}

	}
}
