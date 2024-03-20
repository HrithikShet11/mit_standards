package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type CFramework struct {
	Framework    string  `json:"Framework"`
	Version      string  `json:"Version"`
	Provider     string  `json:"Provider"`
	Description  string  `json:"Description"`
	Requirements []check `json:"Requirements"`
}

type check struct {
	Id          string `json:"Id"`
	Description string `json:"Description"`
	Attributes  []struct {
		Name                      string `json:"Name"`
		WellArchitectedQuestionId string `json:"WellArchitectedQuestionId"`
		WellArchitectedPracticeId string `json:"WellArchitectedPracticeId"`
		Section                   string `json:"Section"`
		SubSection                string `json:"SubSection"`
		LevelOfRisk               string `json:"LevelOfRisk"`
		AssessmentMethod          string `json:"AssessmentMethod"`
		ImplementationGuidanceUrl string `json:"ImplementationGuidanceUrl"`
	} `json:"Attributes"`
	Checks []string `json:"Checks"`
}

func main() {
	// JSON data
	jsonData := `{
		"Framework": "AWS-Well-Architected-Framework-Security-Pillar",
		"Version": "",
		"Provider": "AWS",
		"Description": "Best Practices for AWS Well-Architected Framework Security Pillar. The focus of this framework is the security pillar of the AWS Well-Architected Framework. It provides guidance to help you apply best practices, current recommendations in the design, delivery, and maintenance of secure AWS workloads.",
		"Requirements": [
		  {
			"Id": "SEC01-BP01",
			"Description": "Establish common guardrails and isolation between environments (such as production, development, and test) and workloads through a multi-account strategy. Account-level separation is strongly recommended, as it provides a strong isolation boundary for security, billing, and access.",
			"Attributes": [
			  {
				"Name": "SEC01-BP01 Separate workloads using accounts",
				"WellArchitectedQuestionId": "securely-operate",
				"WellArchitectedPracticeId": "sec_securely_operate_multi_accounts",
				"Section": "Security foundations",
				"SubSection": "AWS account management and separation",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Establish common guardrails and isolation between environments (such as production, development, and test) and workloads through a multi-account strategy. Account-level separation is strongly recommended, as it provides a strong isolation boundary for security, billing, and access.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_multi_accounts.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "organizations_account_part_of_organizations"
			]
		  },
		  {
			"Id": "SEC01-BP02",
			"Description": "The root user is the most privileged user in an AWS account, with full administrative access to all resources within the account, and in some cases cannot be constrained by security policies. Deactivating programmatic access to the root user, establishing appropriate controls for the root user, and avoiding routine use of the root user helps reduce the risk of inadvertent exposure of the root credentials and subsequent compromise of the cloud environment.",
			"Attributes": [
			  {
				"Name": "SEC01-BP02 Secure account root user and properties",
				"WellArchitectedQuestionId": "securely-operate",
				"WellArchitectedPracticeId": "sec_securely_operate_aws_account",
				"Section": "Security foundations",
				"SubSection": "AWS account management and separation",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "The root user is the most privileged user in an AWS account, with full administrative access to all resources within the account, and in some cases cannot be constrained by security policies. Deactivating programmatic access to the root user, establishing appropriate controls for the root user, and avoiding routine use of the root user helps reduce the risk of inadvertent exposure of the root credentials and subsequent compromise of the cloud environment.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_aws_account.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "iam_root_hardware_mfa_enabled",
			  "iam_root_mfa_enabled",
			  "iam_no_root_access_key"
			]
		  },
		  {
			"Id": "SEC01-BP03",
			"Description": "Based on your compliance requirements and risks identified from your threat model, derive and validate the control objectives and controls that you need to apply to your workload. Ongoing validation of control objectives and controls help you measure the effectiveness of risk mitigation.",
			"Attributes": [
			  {
				"Name": "SEC01-BP03 Identify and validate control objectives",
				"WellArchitectedQuestionId": "securely-operate",
				"WellArchitectedPracticeId": "sec_securely_operate_control_objectives",
				"Section": "Security foundations",
				"SubSection": "Operating your workloads securely",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Based on your compliance requirements and risks identified from your threat model, derive and validate the control objectives and controls that you need to apply to your workload. Ongoing validation of control objectives and controls help you measure the effectiveness of risk mitigation.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_control_objectives.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC01-BP04",
			"Description": "To help you define and implement appropriate controls, recognize attack vectors by staying up to date with the latest security threats. Consume AWS Managed Services to make it easier to receive notification of unexpected or unusual behavior in your AWS accounts. Investigate using AWS Partner tools or third-party threat information feeds as part of your security information flow. The Common Vulnerabilities and Exposures (CVE) List  list contains publicly disclosed cyber security vulnerabilities that you can use to stay up to date.",
			"Attributes": [
			  {
				"Name": "SEC01-BP04 Keep up-to-date with security threats",
				"WellArchitectedQuestionId": "securely-operate",
				"WellArchitectedPracticeId": "sec_securely_operate_updated_threats",
				"Section": "Security foundations",
				"SubSection": "Operating your workloads securely",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "To help you define and implement appropriate controls, recognize attack vectors by staying up to date with the latest security threats. Consume AWS Managed Services to make it easier to receive notification of unexpected or unusual behavior in your AWS accounts. Investigate using AWS Partner tools or third-party threat information feeds as part of your security information flow. The Common Vulnerabilities and Exposures (CVE) List  list contains publicly disclosed cyber security vulnerabilities that you can use to stay up to date.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_updated_threats.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC01-BP05",
			"Description": "Stay up-to-date with both AWS and industry security recommendations to evolve the security posture of your workload. AWS Security Bulletins contain important information about security and privacy notifications.",
			"Attributes": [
			  {
				"Name": "SEC01-BP05 Keep up-to-date with security recommendations",
				"WellArchitectedQuestionId": "securely-operate",
				"WellArchitectedPracticeId": "sec_securely_operate_updated_recommendations",
				"Section": "Security foundations",
				"SubSection": "Operating your workloads securely",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Stay up-to-date with both AWS and industry security recommendations to evolve the security posture of your workload. AWS Security Bulletins contain important information about security and privacy notifications.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_updated_recommendations.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC01-BP06",
			"Description": "Establish secure baselines and templates for security mechanisms that are tested and validated as part of your build, pipelines, and processes. Use tools and automation to test and validate all security controls continuously. For example, scan items such as machine images and infrastructure-as-code templates for security vulnerabilities, irregularities, and drift from an established baseline at each stage. AWS CloudFormation Guard can help you verify that CloudFormation templates are safe, save you time, and reduce the risk of configuration error.Reducing the number of security misconfigurations introduced into a production environment is critical—the more quality control and reduction of defects you can perform in the build process, the better. Design continuous integration and continuous deployment (CI/CD) pipelines to test for security issues whenever possible. CI/CD pipelines offer the opportunity to enhance security at each stage of build and delivery. CI/CD security tooling must also be kept updated to mitigate evolving threats.Track changes to your workload configuration to help with compliance auditing, change management, and investigations that may apply to you. You can use AWS Config to record and evaluate your AWS and third-party resources. It allows you to continuously audit and assess the overall compliance with rules and conformance packs, which are collections of rules with remediation actions.Change tracking should include planned changes, which are part of your organization's change control process (sometimes referred to as MACD—Move, Add, Change, Delete), unplanned changes, and unexpected changes, such as incidents. Changes might occur on the infrastructure, but they might also be related to other categories, such as changes in code repositories, machine images and application inventory changes, process and policy changes, or documentation changes.",
			"Attributes": [
			  {
				"Name": "SEC01-BP06 Automate testing and validation of security controls in pipelines",
				"WellArchitectedQuestionId": "securely-operate",
				"WellArchitectedPracticeId": "sec_securely_operate_test_validate_pipeline",
				"Section": "Security foundations",
				"SubSection": "Operating your workloads securely",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Establish secure baselines and templates for security mechanisms that are tested and validated as part of your build, pipelines, and processes. Use tools and automation to test and validate all security controls continuously. For example, scan items such as machine images and infrastructure-as-code templates for security vulnerabilities, irregularities, and drift from an established baseline at each stage. AWS CloudFormation Guard can help you verify that CloudFormation templates are safe, save you time, and reduce the risk of configuration error.Reducing the number of security misconfigurations introduced into a production environment is critical—the more quality control and reduction of defects you can perform in the build process, the better. Design continuous integration and continuous deployment (CI/CD) pipelines to test for security issues whenever possible. CI/CD pipelines offer the opportunity to enhance security at each stage of build and delivery. CI/CD security tooling must also be kept updated to mitigate evolving threats.Track changes to your workload configuration to help with compliance auditing, change management, and investigations that may apply to you. You can use AWS Config to record and evaluate your AWS and third-party resources. It allows you to continuously audit and assess the overall compliance with rules and conformance packs, which are collections of rules with remediation actions.Change tracking should include planned changes, which are part of your organization's change control process (sometimes referred to as MACD—Move, Add, Change, Delete), unplanned changes, and unexpected changes, such as incidents. Changes might occur on the infrastructure, but they might also be related to other categories, such as changes in code repositories, machine images and application inventory changes, process and policy changes, or documentation changes.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_test_validate_pipeline.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "ec2_instance_managed_by_ssm",
			  "ecr_repositories_scan_images_on_push_enabled",
			  "ecr_repositories_scan_vulnerabilities_in_latest_image"
			]
		  },
		  {
			"Id": "SEC01-BP07",
			"Description": "Perform threat modeling to identify and maintain an up-to-date register of potential threats and associated mitigations for your workload. Prioritize your threats and adapt your security control mitigations to prevent, detect, and respond. Revisit and maintain this in the context of your workload, and the evolving security landscape.",
			"Attributes": [
			  {
				"Name": "SEC01-BP07 Identify threats and prioritize mitigations using a threat model",
				"WellArchitectedQuestionId": "securely-operate",
				"WellArchitectedPracticeId": "sec_securely_operate_threat_model",
				"Section": "Security foundations",
				"SubSection": "Operating your workloads securely",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Perform threat modeling to identify and maintain an up-to-date register of potential threats and associated mitigations for your workload. Prioritize your threats and adapt your security control mitigations to prevent, detect, and respond. Revisit and maintain this in the context of your workload, and the evolving security landscape.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_threat_model.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "wellarchitected_workload_no_high_or_medium_risks"
			]
		  },
		  {
			"Id": "SEC01-BP08",
			"Description": "Evaluate and implement security services and features from AWS and AWS Partners that allow you to evolve the security posture of your workload. The AWS Security Blog highlights new AWS services and features, implementation guides, and general security guidance. What's New with AWS? is a great way to stay up to date with all new AWS features, services, and announcements.",
			"Attributes": [
			  {
				"Name": "SEC01-BP08 Evaluate and implement new security services and features regularly",
				"WellArchitectedQuestionId": "securely-operate",
				"WellArchitectedPracticeId": "sec_securely_operate_implement_services_features",
				"Section": "Security foundations",
				"SubSection": "Operating your workloads securely",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Evaluate and implement security services and features from AWS and AWS Partners that allow you to evolve the security posture of your workload. The AWS Security Blog highlights new AWS services and features, implementation guides, and general security guidance. What's New with AWS? is a great way to stay up to date with all new AWS features, services, and announcements.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_implement_services_features.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC02-BP01",
			"Description": "Sign-ins (authentication using sign-in credentials) can present risks when not using mechanisms like multi-factor authentication (MFA), especially in situations where sign-in credentials have been inadvertently disclosed or are easily guessed. Use strong sign-in mechanisms to reduce these risks by requiring MFA and strong password policies.",
			"Attributes": [
			  {
				"Name": "SEC02-BP01 Use strong sign-in mechanisms",
				"WellArchitectedQuestionId": "identities",
				"WellArchitectedPracticeId": "sec_identities_enforce_mechanisms",
				"Section": "Identity and access management",
				"SubSection": "Identity management",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Sign-ins (authentication using sign-in credentials) can present risks when not using mechanisms like multi-factor authentication (MFA), especially in situations where sign-in credentials have been inadvertently disclosed or are easily guessed. Use strong sign-in mechanisms to reduce these risks by requiring MFA and strong password policies.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_enforce_mechanisms.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "iam_password_policy_lowercase",
			  "iam_password_policy_minimum_length_14",
			  "iam_password_policy_number",
			  "iam_password_policy_reuse_24",
			  "iam_password_policy_symbol",
			  "iam_password_policy_uppercase",
			  "directoryservice_radius_server_security_protocol",
			  "directoryservice_supported_mfa_radius_enabled",
			  "iam_user_hardware_mfa_enabled",
			  "iam_user_mfa_enabled_console_access",
			  "iam_user_two_active_access_key",
			  "iam_user_no_setup_initial_access_key",
			  "opensearch_service_domains_use_cognito_authentication_for_kibana",
			  "sagemaker_notebook_instance_root_access_disabled",
			  "iam_avoid_root_usage"
			]
		  },
		  {
			"Id": "SEC02-BP02",
			"Description": "When doing any type of authentication, it’s best to use temporary credentials instead of long-term credentials to reduce or eliminate risks, such as credentials being inadvertently disclosed, shared, or stolen.",
			"Attributes": [
			  {
				"Name": "SEC02-BP02 Use temporary credentials",
				"WellArchitectedQuestionId": "identities",
				"WellArchitectedPracticeId": "sec_identities_unique",
				"Section": "Identity and access management",
				"SubSection": "Identity management",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "When doing any type of authentication, it’s best to use temporary credentials instead of long-term credentials to reduce or eliminate risks, such as credentials being inadvertently disclosed, shared, or stolen.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_unique.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "iam_rotate_access_key_90_days"
			]
		  },
		  {
			"Id": "SEC02-BP03",
			"Description": "A workload requires an automated capability to prove its identity to databases, resources, and third-party services. This is accomplished using secret access credentials, such as API access keys, passwords, and OAuth tokens. Using a purpose-built service to store, manage, and rotate these credentials helps reduce the likelihood that those credentials become compromised.",
			"Attributes": [
			  {
				"Name": "SEC02-BP03 Store and use secrets securely",
				"WellArchitectedQuestionId": "identities",
				"WellArchitectedPracticeId": "sec_identities_secrets",
				"Section": "Identity and access management",
				"SubSection": "Identity management",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "A workload requires an automated capability to prove its identity to databases, resources, and third-party services. This is accomplished using secret access credentials, such as API access keys, passwords, and OAuth tokens. Using a purpose-built service to store, manage, and rotate these credentials helps reduce the likelihood that those credentials become compromised.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_secrets.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "autoscaling_find_secrets_ec2_launch_configuration",
			  "awslambda_function_no_secrets_in_code",
			  "awslambda_function_no_secrets_in_variables",
			  "cloudformation_stack_outputs_find_secrets",
			  "ec2_instance_secrets_user_data",
			  "ecs_task_definitions_no_environment_secrets",
			  "ssm_document_secrets"
			]
		  },
		  {
			"Id": "SEC02-BP04",
			"Description": "For workforce identities, rely on an identity provider that enables you to manage identities in a centralized place. This makes it easier to manage access across multiple applications and services, because you are creating, managing, and revoking access from a single location. For example, if someone leaves your organization, you can revoke access for all applications and services (including AWS) from one location. This reduces the need for multiple credentials and provides an opportunity to integrate with existing human resources (HR) processes. For federation with individual AWS accounts, you can use centralized identities for AWS with a SAML 2.0-based provider with AWS Identity and Access Management. You can use any provider— whether hosted by you in AWS, external to AWS, or supplied by the AWS Partner—that is compatible with the SAML 2.0 protocol. You can use federation between your AWS account and your chosen provider to grant a user or application access to call AWS API operations by using a SAML assertion to get temporary security credentials. Web-based single sign-on is also supported, allowing users to sign in to the AWS Management Console from your sign in website. For federation to multiple accounts in your AWS Organizations, you can configure your identity source in AWS IAM Identity Center (successor to AWS Single Sign-On) (IAM Identity Center), and specify where your users and groups are stored. Once configured, your identity provider is your source of truth, and information can be synchronized using the System for Cross-domain Identity Management (SCIM) v2.0 protocol. You can then look up users or groups and grant them IAM Identity Center access to AWS accounts, cloud applications, or both. IAM Identity Center integrates with AWS Organizations, which enables you to configure your identity provider once and then grant access to existing and new accounts managed in your organization. IAM Identity Center provides you with a default store, which you can use to manage your users and groups. If you choose to use the IAM Identity Center store, create your users and groups and assign their level of access to your AWS accounts and applications, keeping in mind the best practice of least privilege. Alternatively, you can choose to Connect to Your External Identity Provider using SAML 2.0, or Connect to Your Microsoft AD Directory using AWS Directory Service. Once configured, you can sign into the AWS Management Console, or the AWS mobile app, by authenticating through your central identity provider. For managing end-users or consumers of your workloads, such as a mobile app, you can use Amazon Cognito. It provides authentication, authorization, and user management for your web and mobile apps. Your users can sign in directly with sign-in credentials, or through a third party, such as Amazon, Apple, Facebook, or Google.",
			"Attributes": [
			  {
				"Name": "SEC02-BP04 Rely on a centralized identity provider",
				"WellArchitectedQuestionId": "identities",
				"WellArchitectedPracticeId": "sec_identities_identity_provider",
				"Section": "Identity and access management",
				"SubSection": "Identity management",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "For workforce identities, rely on an identity provider that enables you to manage identities in a centralized place. This makes it easier to manage access across multiple applications and services, because you are creating, managing, and revoking access from a single location. For example, if someone leaves your organization, you can revoke access for all applications and services (including AWS) from one location. This reduces the need for multiple credentials and provides an opportunity to integrate with existing human resources (HR) processes. For federation with individual AWS accounts, you can use centralized identities for AWS with a SAML 2.0-based provider with AWS Identity and Access Management. You can use any provider— whether hosted by you in AWS, external to AWS, or supplied by the AWS Partner—that is compatible with the SAML 2.0 protocol. You can use federation between your AWS account and your chosen provider to grant a user or application access to call AWS API operations by using a SAML assertion to get temporary security credentials. Web-based single sign-on is also supported, allowing users to sign in to the AWS Management Console from your sign in website. For federation to multiple accounts in your AWS Organizations, you can configure your identity source in AWS IAM Identity Center (successor to AWS Single Sign-On) (IAM Identity Center), and specify where your users and groups are stored. Once configured, your identity provider is your source of truth, and information can be synchronized using the System for Cross-domain Identity Management (SCIM) v2.0 protocol. You can then look up users or groups and grant them IAM Identity Center access to AWS accounts, cloud applications, or both. IAM Identity Center integrates with AWS Organizations, which enables you to configure your identity provider once and then grant access to existing and new accounts managed in your organization. IAM Identity Center provides you with a default store, which you can use to manage your users and groups. If you choose to use the IAM Identity Center store, create your users and groups and assign their level of access to your AWS accounts and applications, keeping in mind the best practice of least privilege. Alternatively, you can choose to Connect to Your External Identity Provider using SAML 2.0, or Connect to Your Microsoft AD Directory using AWS Directory Service. Once configured, you can sign into the AWS Management Console, or the AWS mobile app, by authenticating through your central identity provider. For managing end-users or consumers of your workloads, such as a mobile app, you can use Amazon Cognito. It provides authentication, authorization, and user management for your web and mobile apps. Your users can sign in directly with sign-in credentials, or through a third party, such as Amazon, Apple, Facebook, or Google.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_identity_provider.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "iam_role_cross_service_confused_deputy_prevention"
			]
		  },
		  {
			"Id": "SEC02-BP05",
			"Description": "When you cannot rely on temporary credentials and require long-term credentials, audit credentials to ensure that the defined controls for example, multi-factor authentication (MFA), are enforced, rotated regularly, and have the appropriate access level. Periodic validation, preferably through an automated tool, is necessary to verify that the correct controls are enforced. For human identities, you should require users to change their passwords periodically and retire access keys in favor of temporary credentials. As you are moving from users to centralized identities, you can generate a credential report to audit your users. We also recommend that you enforce MFA settings in your identity provider. You can set up AWS Config Rules to monitor these settings. For machine identities, you should rely on temporary credentials using IAM roles. For situations where this is not possible, frequent auditing and rotating access keys is necessary.",
			"Attributes": [
			  {
				"Name": "SEC02-BP05 Audit and rotate credentials periodically",
				"WellArchitectedQuestionId": "identities",
				"WellArchitectedPracticeId": "sec_identities_audit",
				"Section": "Identity and access management",
				"SubSection": "Identity management",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "When you cannot rely on temporary credentials and require long-term credentials, audit credentials to ensure that the defined controls for example, multi-factor authentication (MFA), are enforced, rotated regularly, and have the appropriate access level. Periodic validation, preferably through an automated tool, is necessary to verify that the correct controls are enforced. For human identities, you should require users to change their passwords periodically and retire access keys in favor of temporary credentials. As you are moving from users to centralized identities, you can generate a credential report to audit your users. We also recommend that you enforce MFA settings in your identity provider. You can set up AWS Config Rules to monitor these settings. For machine identities, you should rely on temporary credentials using IAM roles. For situations where this is not possible, frequent auditing and rotating access keys is necessary.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_audit.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "iam_rotate_access_key_90_days",
			  "kms_cmk_rotation_enabled",
			  "secretsmanager_automatic_rotation_enabled"
			]
		  },
		  {
			"Id": "SEC02-BP06",
			"Description": "As the number of users you manage grows, you will need to determine ways to organize them so that you can manage them at scale. Place users with common security requirements in groups defined by your identity provider, and put mechanisms in place to ensure that user attributes that may be used for access control (for example, department or location) are correct and updated. Use these groups and attributes to control access, rather than individual users. This allows you to manage access centrally by changing a user's group membership or attributes once with a permission set, rather than updating many individual policies when a user's access needs change. You can use AWS IAM Identity Center (successor to AWS Single Sign-On) (IAM Identity Center) to manage user groups and attributes. IAM Identity Center supports most commonly used attributes whether they are entered manually during user creation or automatically provisioned using a synchronization engine, such as defined in the System for Cross-Domain Identity Management (SCIM) specification.",
			"Attributes": [
			  {
				"Name": "SEC02-BP06 Leverage user groups and attributes",
				"WellArchitectedQuestionId": "identities",
				"WellArchitectedPracticeId": "sec_identities_groups_attributes",
				"Section": "Identity and access management",
				"SubSection": "Identity management",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "As the number of users you manage grows, you will need to determine ways to organize them so that you can manage them at scale. Place users with common security requirements in groups defined by your identity provider, and put mechanisms in place to ensure that user attributes that may be used for access control (for example, department or location) are correct and updated. Use these groups and attributes to control access, rather than individual users. This allows you to manage access centrally by changing a user's group membership or attributes once with a permission set, rather than updating many individual policies when a user's access needs change. You can use AWS IAM Identity Center (successor to AWS Single Sign-On) (IAM Identity Center) to manage user groups and attributes. IAM Identity Center supports most commonly used attributes whether they are entered manually during user creation or automatically provisioned using a synchronization engine, such as defined in the System for Cross-Domain Identity Management (SCIM) specification.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_groups_attributes.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "iam_policy_allows_privilege_escalation",
			  "iam_policy_attached_only_to_group_or_roles"
			]
		  },
		  {
			"Id": "SEC03-BP01",
			"Description": "Each component or resource of your workload needs to be accessed by administrators, end users, or other components. Have a clear definition of who or what should have access to each component, choose the appropriate identity type and method of authentication and authorization.",
			"Attributes": [
			  {
				"Name": "SEC03-BP01 Define access requirements",
				"WellArchitectedQuestionId": "permissions",
				"WellArchitectedPracticeId": "sec_permissions_define",
				"Section": "Identity and access management",
				"SubSection": "Permissions management",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Each component or resource of your workload needs to be accessed by administrators, end users, or other components. Have a clear definition of who or what should have access to each component, choose the appropriate identity type and method of authentication and authorization.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_define.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "ec2_instance_imdsv2_enabled",
			  "ec2_instance_profile_attached",
			  "cloudwatch_cross_account_sharing_disabled"
			]
		  },
		  {
			"Id": "SEC03-BP02",
			"Description": "Grant only the access that identities require by allowing access to specific actions on specific AWS resources under specific conditions. Rely on groups and identity attributes to dynamically set permissions at scale, rather than defining permissions for individual users. For example, you can allow a group of developers access to manage only resources for their project. This way, when a developer is removed from the group, access for the developer is revoked everywhere that group was used for access control, without requiring any changes to the access policies.",
			"Attributes": [
			  {
				"Name": "SEC03-BP02 Grant least privilege access",
				"WellArchitectedQuestionId": "permissions",
				"WellArchitectedPracticeId": "sec_permissions_least_privileges",
				"Section": "Identity and access management",
				"SubSection": "Permissions management",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Grant only the access that identities require by allowing access to specific actions on specific AWS resources under specific conditions. Rely on groups and identity attributes to dynamically set permissions at scale, rather than defining permissions for individual users. For example, you can allow a group of developers access to manage only resources for their project. This way, when a developer is removed from the group, access for the developer is revoked everywhere that group was used for access control, without requiring any changes to the access policies.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_least_privileges.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "ec2_instance_profile_attached",
			  "iam_aws_attached_policy_no_administrative_privileges",
			  "iam_customer_attached_policy_no_administrative_privileges",
			  "iam_customer_unattached_policy_no_administrative_privileges",
			  "iam_inline_policy_no_administrative_privileges",
			  "opensearch_service_domains_internal_user_database_enabled"
			]
		  },
		  {
			"Id": "SEC03-BP03",
			"Description": "A process that allows emergency access to your workload in the unlikely event of an automated process or pipeline issue. This will help you rely on least privilege access, but ensure users can obtain the right level of access when they require it. For example, establish a process for administrators to verify and approve their request, such as an emergency AWS cross-account role for access, or a specific process for administrators to follow to validate and approve an emergency request.",
			"Attributes": [
			  {
				"Name": "SEC03-BP03 Establish emergency access process",
				"WellArchitectedQuestionId": "permissions",
				"WellArchitectedPracticeId": "sec_permissions_emergency_process",
				"Section": "Identity and access management",
				"SubSection": "Permissions management",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "A process that allows emergency access to your workload in the unlikely event of an automated process or pipeline issue. This will help you rely on least privilege access, but ensure users can obtain the right level of access when they require it. For example, establish a process for administrators to verify and approve their request, such as an emergency AWS cross-account role for access, or a specific process for administrators to follow to validate and approve an emergency request.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_emergency_process.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "account_maintain_current_contact_details",
			  "account_security_contact_information_is_registered",
			  "account_security_questions_are_registered_in_the_aws_account"
			]
		  },
		  {
			"Id": "SEC03-BP04",
			"Description": "As your teams determine what access is required, remove unneeded permissions and establish review processes to achieve least privilege permissions. Continually monitor and remove unused identities and permissions for both human and machine access.",
			"Attributes": [
			  {
				"Name": "SEC03-BP04 Reduce permissions continuously",
				"WellArchitectedQuestionId": "permissions",
				"WellArchitectedPracticeId": "sec_permissions_continuous_reduction",
				"Section": "Identity and access management",
				"SubSection": "Permissions management",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "As your teams determine what access is required, remove unneeded permissions and establish review processes to achieve least privilege permissions. Continually monitor and remove unused identities and permissions for both human and machine access.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_continuous_reduction.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "iam_customer_attached_policy_no_administrative_privileges",
			  "iam_customer_unattached_policy_no_administrative_privileges"
			]
		  },
		  {
			"Id": "SEC03-BP05",
			"Description": "Establish common controls that restrict access to all identities in your organization. For example, you can restrict access to specific AWS Regions, or prevent your operators from deleting common resources, such as an IAM role used for your central security team.",
			"Attributes": [
			  {
				"Name": "SEC03-BP05 Define permission guardrails for your organization",
				"WellArchitectedQuestionId": "permissions",
				"WellArchitectedPracticeId": "sec_permissions_define_guardrails",
				"Section": "Identity and access management",
				"SubSection": "Permissions management",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Establish common controls that restrict access to all identities in your organization. For example, you can restrict access to specific AWS Regions, or prevent your operators from deleting common resources, such as an IAM role used for your central security team.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_define_guardrails.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "organizations_account_part_of_organizations"
			]
		  },
		  {
			"Id": "SEC03-BP06",
			"Description": "Integrate access controls with operator and application lifecycle and your centralized federation provider. For example, remove a user's access when they leave the organization or change roles. As you manage workloads using separate accounts, there will be cases where you need to share resources between those accounts. We recommend that you share resources using AWS Resource Access Manager (AWS RAM). This service enables you to easily and securely share AWS resources within your AWS Organizations and Organizational Units. Using AWS RAM, access to shared resources is automatically granted or revoked as accounts are moved in and out of the Organization or Organization Unit with which they are shared. This helps ensure that resources are only shared with the accounts that you intend.",
			"Attributes": [
			  {
				"Name": "SEC03-BP06 Manage access based on lifecycle",
				"WellArchitectedQuestionId": "permissions",
				"WellArchitectedPracticeId": "sec_permissions_lifecycle",
				"Section": "Identity and access management",
				"SubSection": "Permissions management",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Integrate access controls with operator and application lifecycle and your centralized federation provider. For example, remove a user's access when they leave the organization or change roles. As you manage workloads using separate accounts, there will be cases where you need to share resources between those accounts. We recommend that you share resources using AWS Resource Access Manager (AWS RAM). This service enables you to easily and securely share AWS resources within your AWS Organizations and Organizational Units. Using AWS RAM, access to shared resources is automatically granted or revoked as accounts are moved in and out of the Organization or Organization Unit with which they are shared. This helps ensure that resources are only shared with the accounts that you intend.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_lifecycle.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "appstream_fleet_maximum_session_duration",
			  "appstream_fleet_session_disconnect_timeout",
			  "appstream_fleet_session_idle_disconnect_timeout",
			  "cloudwatch_log_group_retention_policy_specific_days_enabled",
			  "codebuild_project_older_90_days",
			  "ec2_elastic_ip_unassigned",
			  "ecr_repositories_lifecycle_policy_enabled",
			  "elbv2_listeners_underneath",
			  "iam_password_policy_expires_passwords_within_90_days_or_less"
			]
		  },
		  {
			"Id": "SEC03-BP07",
			"Description": "Continuously monitor findings that highlight public and cross-account access. Reduce public access and cross-account access to only resources that require this type of access.",
			"Attributes": [
			  {
				"Name": "SEC03-BP07 Analyze public and cross-account access",
				"WellArchitectedQuestionId": "permissions",
				"WellArchitectedPracticeId": "sec_permissions_analyze_cross_account",
				"Section": "Identity and access management",
				"SubSection": "Permissions management",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Continuously monitor findings that highlight public and cross-account access. Reduce public access and cross-account access to only resources that require this type of access.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_analyze_cross_account.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "ec2_ebs_public_snapshot",
			  "ec2_instance_public_ip",
			  "opensearch_service_domains_not_publicly_accessible",
			  "emr_cluster_master_nodes_no_public_ip",
			  "emr_cluster_account_public_block_enabled",
			  "emr_cluster_publicly_accesible",
			  "glacier_vaults_policy_public_access",
			  "awslambda_function_not_publicly_accessible",
			  "awslambda_function_not_publicly_accessible",
			  "rds_instance_no_public_access",
			  "rds_snapshots_public_access",
			  "kms_key_not_publicly_accessible",
			  "opensearch_service_domains_not_publicly_accessible",
			  "redshift_cluster_public_access",
			  "s3_account_level_public_access_blocks",
			  "s3_bucket_public_access",
			  "s3_bucket_policy_public_write_access",
			  "sagemaker_notebook_instance_without_direct_internet_access_configured",
			  "appstream_fleet_default_internet_access_disabled",
			  "apigateway_restapi_public",
			  "awslambda_function_url_cors_policy",
			  "awslambda_function_url_public",
			  "cloudtrail_logs_s3_bucket_is_not_publicly_accessible",
			  "codeartifact_packages_external_public_publishing_disabled",
			  "ecr_repositories_not_publicly_accessible",
			  "efs_not_publicly_accessible",
			  "eks_endpoints_not_publicly_accessible",
			  "elb_internet_facing",
			  "elbv2_internet_facing",
			  "s3_account_level_public_access_blocks",
			  "sns_topics_not_publicly_accessible",
			  "sqs_queues_not_publicly_accessible",
			  "ssm_documents_set_as_public",
			  "ec2_securitygroup_allow_wide_open_public_ipv4",
			  "ec2_ami_public"
			]
		  },
		  {
			"Id": "SEC03-BP08",
			"Description": "Govern the consumption of shared resources across accounts or within your AWS Organizations. Monitor shared resources and review shared resource access.",
			"Attributes": [
			  {
				"Name": "SEC03-BP08 Share resources securely within your organization",
				"WellArchitectedQuestionId": "permissions",
				"WellArchitectedPracticeId": "sec_permissions_share_securely",
				"Section": "Identity and access management",
				"SubSection": "Permissions management",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Govern the consumption of shared resources across accounts or within your AWS Organizations. Monitor shared resources and review shared resource access.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_share_securely.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "opensearch_service_domains_not_publicly_accessible",
			  "awslambda_function_not_publicly_accessible",
			  "sagemaker_notebook_instance_without_direct_internet_access_configured",
			  "ssm_document_secrets",
			  "codebuild_project_user_controlled_buildspec"
			]
		  },
		  {
			"Id": "SEC04-BP01",
			"Description": "Retain security event logs from services and applications. This is a fundamental principle of security for audit, investigations, and operational use cases, and a common security requirement driven by governance, risk, and compliance (GRC) standards, policies, and procedures.",
			"Attributes": [
			  {
				"Name": "SEC04-BP01 Configure service and application logging",
				"WellArchitectedQuestionId": "detect-investigate-events",
				"WellArchitectedPracticeId": "sec_detect_investigate_events_app_service_logging",
				"Section": "Detection",
				"SubSection": "Detection",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Retain security event logs from services and applications. This is a fundamental principle of security for audit, investigations, and operational use cases, and a common security requirement driven by governance, risk, and compliance (GRC) standards, policies, and procedures.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_detect_investigate_events_app_service_logging.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "apigateway_restapi_logging_enabled",
			  "opensearch_service_domains_audit_logging_enabled",
			  "cloudtrail_cloudwatch_logging_enabled",
			  "cloudtrail_s3_dataevents_read_enabled",
			  "cloudtrail_s3_dataevents_write_enabled",
			  "acm_certificates_transparency_logs_enabled",
			  "apigatewayv2_api_access_logging_enabled",
			  "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
			  "cloudfront_distributions_logging_enabled",
			  "cloudtrail_cloudwatch_logging_enabled",
			  "cloudtrail_logs_s3_bucket_access_logging_enabled",
			  "directoryservice_directory_log_forwarding_enabled",
			  "eks_control_plane_logging_all_types_enabled",
			  "elb_logging_enabled",
			  "elbv2_logging_enabled",
			  "opensearch_service_domains_cloudwatch_logging_enabled",
			  "rds_instance_integration_cloudwatch_logs",
			  "redshift_cluster_audit_logging",
			  "route53_public_hosted_zones_cloudwatch_logging_enabled",
			  "s3_bucket_server_access_logging_enabled",
			  "vpc_flow_logs_enabled"
			]
		  },
		  {
			"Id": "SEC04-BP02",
			"Description": "Security operations teams rely on the collection of logs and the use of search tools to discover potential events of interest, which might indicate unauthorized activity or unintentional change. However, simply analyzing collected data and manually processing information is insufficient to keep up with the volume of information flowing from complex architectures. Analysis and reporting alone don't facilitate the assignment of the right resources to work an event in a timely fashion. A best practice for building a mature security operations team is to deeply integrate the flow of security events and findings into a notification and workflow system such as a ticketing system, a bug or issue system, or other security information and event management (SIEM) system. This takes the workflow out of email and static reports, and allows you to route, escalate, and manage events or findings. Many organizations are also integrating security alerts into their chat or collaboration, and developer productivity platforms. For organizations embarking on automation, an API-driven, low-latency ticketing system offers considerable flexibility when planning what to automate first. This best practice applies not only to security events generated from log messages depicting user activity or network events, but also from changes detected in the infrastructure itself. The ability to detect change, determine whether a change was appropriate, and then route that information to the correct remediation workflow is essential in maintaining and validating a secure architecture, in the context of changes where the nature of their undesirability is sufficiently subtle that their execution cannot currently be prevented with a combination of AWS Identity and Access Management (IAM) and AWS Organizations configuration. Amazon GuardDuty and AWS Security Hub provide aggregation, deduplication, and analysis mechanisms for log records that are also made available to you via other AWS services. GuardDuty ingests, aggregates, and analyzes information from sources such as AWS CloudTrail management and data events, VPC DNS logs, and VPC Flow Logs. Security Hub can ingest, aggregate, and analyze output from GuardDuty, AWS Config, Amazon Inspector, Amazon Macie, AWS Firewall Manager, and a significant number of third-party security products available in the AWS Marketplace, and if built accordingly, your own code. Both GuardDuty and Security Hub have an Administrator-Member model that can aggregate findings and insights across multiple accounts, and Security Hub is often used by customers who have an on- premises SIEM as an AWS-side log and alert preprocessor and aggregator from which they can then ingest Amazon EventBridge through a AWS Lambda-based processor and forwarder.",
			"Attributes": [
			  {
				"Name": "SEC04-BP02 Analyze logs, findings, and metrics centrally",
				"WellArchitectedQuestionId": "detect-investigate-events",
				"WellArchitectedPracticeId": "sec_detect_investigate_events_analyze_all",
				"Section": "Detection",
				"SubSection": "Detection",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Security operations teams rely on the collection of logs and the use of search tools to discover potential events of interest, which might indicate unauthorized activity or unintentional change. However, simply analyzing collected data and manually processing information is insufficient to keep up with the volume of information flowing from complex architectures. Analysis and reporting alone don't facilitate the assignment of the right resources to work an event in a timely fashion. A best practice for building a mature security operations team is to deeply integrate the flow of security events and findings into a notification and workflow system such as a ticketing system, a bug or issue system, or other security information and event management (SIEM) system. This takes the workflow out of email and static reports, and allows you to route, escalate, and manage events or findings. Many organizations are also integrating security alerts into their chat or collaboration, and developer productivity platforms. For organizations embarking on automation, an API-driven, low-latency ticketing system offers considerable flexibility when planning what to automate first. This best practice applies not only to security events generated from log messages depicting user activity or network events, but also from changes detected in the infrastructure itself. The ability to detect change, determine whether a change was appropriate, and then route that information to the correct remediation workflow is essential in maintaining and validating a secure architecture, in the context of changes where the nature of their undesirability is sufficiently subtle that their execution cannot currently be prevented with a combination of AWS Identity and Access Management (IAM) and AWS Organizations configuration. Amazon GuardDuty and AWS Security Hub provide aggregation, deduplication, and analysis mechanisms for log records that are also made available to you via other AWS services. GuardDuty ingests, aggregates, and analyzes information from sources such as AWS CloudTrail management and data events, VPC DNS logs, and VPC Flow Logs. Security Hub can ingest, aggregate, and analyze output from GuardDuty, AWS Config, Amazon Inspector, Amazon Macie, AWS Firewall Manager, and a significant number of third-party security products available in the AWS Marketplace, and if built accordingly, your own code. Both GuardDuty and Security Hub have an Administrator-Member model that can aggregate findings and insights across multiple accounts, and Security Hub is often used by customers who have an on- premises SIEM as an AWS-side log and alert preprocessor and aggregator from which they can then ingest Amazon EventBridge through a AWS Lambda-based processor and forwarder.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_detect_investigate_events_analyze_all.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "cloudtrail_multi_region_enabled",
			  "vpc_flow_logs_enabled",
			  "config_recorder_all_regions_enabled"
			]
		  },
		  {
			"Id": "SEC04-BP03",
			"Description": "Using automation to investigate and remediate events reduces human effort and error, and enables you to scale investigation capabilities. Regular reviews will help you tune automation tools, and continuously iterate. In AWS, investigating events of interest and information on potentially unexpected changes into an automated workflow can be achieved using Amazon EventBridge. This service provides a scalable rules engine designed to broker both native AWS event formats (such as AWS CloudTrail events), as well as custom events you can generate from your application. Amazon GuardDuty also allows you to route events to a workflow system for those building incident response systems (AWS Step Functions), or to a central Security Account, or to a bucket for further analysis. Detecting change and routing this information to the correct workflow can also be accomplished using AWS Config Rules and Conformance Packs. AWS Config detects changes to in-scope services (though with higher latency than EventBridge) and generates events that can be parsed using AWS Config Rules for rollback, enforcement of compliance policy, and forwarding of information to systems, such as change management platforms and operational ticketing systems. As well as writing your own Lambda functions to respond to AWS Config events, you can also take advantage of the AWS Config Rules Development Kit, and a library of open source AWS Config Rules. Conformance packs are a collection of AWS Config Rules and remediation actions you deploy as a single entity authored as a YAML template. A sample conformance pack template is available for the Well-Architected Security Pillar.",
			"Attributes": [
			  {
				"Name": "SEC04-BP03 Automate response to events",
				"WellArchitectedQuestionId": "detect-investigate-events",
				"WellArchitectedPracticeId": "sec_detect_investigate_events_auto_response",
				"Section": "Detection",
				"SubSection": "Detection",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Using automation to investigate and remediate events reduces human effort and error, and enables you to scale investigation capabilities. Regular reviews will help you tune automation tools, and continuously iterate. In AWS, investigating events of interest and information on potentially unexpected changes into an automated workflow can be achieved using Amazon EventBridge. This service provides a scalable rules engine designed to broker both native AWS event formats (such as AWS CloudTrail events), as well as custom events you can generate from your application. Amazon GuardDuty also allows you to route events to a workflow system for those building incident response systems (AWS Step Functions), or to a central Security Account, or to a bucket for further analysis. Detecting change and routing this information to the correct workflow can also be accomplished using AWS Config Rules and Conformance Packs. AWS Config detects changes to in-scope services (though with higher latency than EventBridge) and generates events that can be parsed using AWS Config Rules for rollback, enforcement of compliance policy, and forwarding of information to systems, such as change management platforms and operational ticketing systems. As well as writing your own Lambda functions to respond to AWS Config events, you can also take advantage of the AWS Config Rules Development Kit, and a library of open source AWS Config Rules. Conformance packs are a collection of AWS Config Rules and remediation actions you deploy as a single entity authored as a YAML template. A sample conformance pack template is available for the Well-Architected Security Pillar.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_detect_investigate_events_auto_response.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "elb_logging_enabled",
			  "cloudtrail_multi_region_enabled",
			  "vpc_flow_logs_enabled"
			]
		  },
		  {
			"Id": "SEC04-BP04",
			"Description": "Create alerts that are sent to and can be actioned by your team. Ensure that alerts include relevant information for the team to take action. For each detective mechanism you have, you should also have a process, in the form of a runbook or playbook, to investigate. For example, when you enable Amazon GuardDuty, it generates different findings. You should have a runbook entry for each finding type, for example, if a trojan is discovered, your runbook has simple instructions that instruct someone to investigate and remediate.",
			"Attributes": [
			  {
				"Name": "SEC04-BP04 Implement actionable security events",
				"WellArchitectedQuestionId": "detect-investigate-events",
				"WellArchitectedPracticeId": "sec_detect_investigate_events_actionable_events",
				"Section": "Detection",
				"SubSection": "Detection",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Create alerts that are sent to and can be actioned by your team. Ensure that alerts include relevant information for the team to take action. For each detective mechanism you have, you should also have a process, in the form of a runbook or playbook, to investigate. For example, when you enable Amazon GuardDuty, it generates different findings. You should have a runbook entry for each finding type, for example, if a trojan is discovered, your runbook has simple instructions that instruct someone to investigate and remediate.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_detect_investigate_events_actionable_events.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "securityhub_enabled",
			  "cloudwatch_changes_to_network_acls_alarm_configured",
			  "cloudwatch_changes_to_network_gateways_alarm_configured",
			  "cloudwatch_changes_to_network_route_tables_alarm_configured",
			  "cloudwatch_changes_to_vpcs_alarm_configured",
			  "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
			  "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled",
			  "cloudwatch_log_metric_filter_authentication_failures",
			  "cloudwatch_log_metric_filter_aws_organizations_changes",
			  "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk",
			  "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes",
			  "cloudwatch_log_metric_filter_policy_changes",
			  "cloudwatch_log_metric_filter_root_usage",
			  "cloudwatch_log_metric_filter_security_group_changes",
			  "cloudwatch_log_metric_filter_sign_in_without_mfa",
			  "cloudwatch_log_metric_filter_unauthorized_api_calls",
			  "directoryservice_directory_monitor_notifications",
			  "guardduty_no_high_severity_findings",
			  "macie_is_enabled",
			  "guardduty_is_enabled"
			]
		  },
		  {
			"Id": "SEC05-BP01",
			"Description": "Group components that share reachability requirements into layers. For example, a database cluster in a virtual private cloud (VPC) with no need for internet access should be placed in subnets with no route to or from the internet. In a serverless workload operating without a VPC, similar layering and segmentation with microservices can achieve the same goal. Components such as Amazon Elastic Compute Cloud (Amazon EC2) instances, Amazon Relational Database Service (Amazon RDS) database clusters, and AWS Lambda functions that share reachability requirements can be segmented into layers formed by subnets. For example, an Amazon RDS database cluster in a VPC with no need for internet access should be placed in subnets with no route to or from the internet. This layered approach for the controls mitigates the impact of a single layer misconfiguration, which could allow unintended access. For Lambda, you can run your functions in your VPC to take advantage of VPC-based controls. For network connectivity that can include thousands of VPCs, AWS accounts, and on-premises networks, you should use AWS Transit Gateway. It acts as a hub that controls how traffic is routed among all the connected networks, which act like spokes. Traffic between an Amazon Virtual Private Cloud and AWS Transit Gateway remains on the AWS private network, which reduces external threat vectors such as distributed denial of service (DDoS) attacks and common exploits, such as SQL injection, cross-site scripting, cross-site request forgery, or abuse of broken authentication code. AWS Transit Gateway inter-region peering also encrypts inter-region traffic with no single point of failure or bandwidth bottleneck.",
			"Attributes": [
			  {
				"Name": "SEC05-BP01 Create network layers",
				"WellArchitectedQuestionId": "network-protection",
				"WellArchitectedPracticeId": "sec_network_protection_create_layers",
				"Section": "Infrastructure protection",
				"SubSection": "Protecting networks",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Group components that share reachability requirements into layers. For example, a database cluster in a virtual private cloud (VPC) with no need for internet access should be placed in subnets with no route to or from the internet. In a serverless workload operating without a VPC, similar layering and segmentation with microservices can achieve the same goal. Components such as Amazon Elastic Compute Cloud (Amazon EC2) instances, Amazon Relational Database Service (Amazon RDS) database clusters, and AWS Lambda functions that share reachability requirements can be segmented into layers formed by subnets. For example, an Amazon RDS database cluster in a VPC with no need for internet access should be placed in subnets with no route to or from the internet. This layered approach for the controls mitigates the impact of a single layer misconfiguration, which could allow unintended access. For Lambda, you can run your functions in your VPC to take advantage of VPC-based controls. For network connectivity that can include thousands of VPCs, AWS accounts, and on-premises networks, you should use AWS Transit Gateway. It acts as a hub that controls how traffic is routed among all the connected networks, which act like spokes. Traffic between an Amazon Virtual Private Cloud and AWS Transit Gateway remains on the AWS private network, which reduces external threat vectors such as distributed denial of service (DDoS) attacks and common exploits, such as SQL injection, cross-site scripting, cross-site request forgery, or abuse of broken authentication code. AWS Transit Gateway inter-region peering also encrypts inter-region traffic with no single point of failure or bandwidth bottleneck.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_network_protection_create_layers.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "opensearch_service_domains_not_publicly_accessible",
			  "awslambda_function_not_publicly_accessible",
			  "apigateway_restapi_waf_acl_attached",
			  "cloudfront_distributions_using_waf",
			  "eks_control_plane_endpoint_access_restricted",
			  "sagemaker_models_network_isolation_enabled",
			  "sagemaker_models_vpc_settings_configured",
			  "sagemaker_notebook_instance_vpc_settings_configured",
			  "sagemaker_training_jobs_network_isolation_enabled",
			  "sagemaker_training_jobs_vpc_settings_configured",
			  "vpc_endpoint_connections_trust_boundaries",
			  "vpc_endpoint_services_allowed_principals_trust_boundaries"
			]
		  },
		  {
			"Id": "SEC05-BP02",
			"Description": "When architecting your network topology, you should examine the connectivity requirements of each component. For example, if a component requires internet accessibility (inbound and outbound), connectivity to VPCs, edge services, and external data centers. A VPC allows you to define your network topology that spans an AWS Region with a private IPv4 address range that you set, or an IPv6 address range AWS selects. You should apply multiple controls with a defense in depth approach for both inbound and outbound traffic, including the use of security groups (stateful inspection firewall), Network ACLs, subnets, and route tables. Within a VPC, you can create subnets in an Availability Zone. Each subnet can have an associated route table that defines routing rules for managing the paths that traffic takes within the subnet. You can define an internet routable subnet by having a route that goes to an internet or NAT gateway attached to the VPC, or through another VPC. When an instance, Amazon Relational Database Service(Amazon RDS) database, or other service is launched within a VPC, it has its own security group per network interface. This firewall is outside the operating system layer and can be used to define rules for allowed inbound and outbound traffic. You can also define relationships between security groups. For example, instances within a database tier security group only accept traffic from instances within the application tier, by reference to the security groups applied to the instances involved. Unless you are using non-TCP protocols, it shouldn't be necessary to have an Amazon Elastic Compute Cloud(Amazon EC2) instance directly accessible by the internet (even with ports restricted by security groups) without a load balancer, or CloudFront. This helps protect it from unintended access through an operating system or application issue. A subnet can also have a network ACL attached to it, which acts as a stateless firewall. You should configure the network ACL to narrow the scope of traffic allowed between layers, note that you need to define both inbound and outbound rules. Some AWS services require components to access the internet for making API calls, where AWS API endpoints are located. Other AWS services use VPC endpoints within your Amazon VPCs. Many AWS services, including Amazon S3 and Amazon DynamoDB, support VPC endpoints, and this technology has been generalized in AWS PrivateLink. We recommend you use this approach to access AWS services, third-party services, and your own services hosted in other VPCs securely. All network traffic on AWS PrivateLink stays on the global AWS backbone and never traverses the internet. Connectivity can only be initiated by the consumer of the service, and not by the provider of the service. Using AWS PrivateLink for external service access allows you to create air-gapped VPCs with no internet access and helps protect your VPCs from external threat vectors. Third-party services can use AWS PrivateLink to allow their customers to connect to the services from their VPCs over private IP addresses. For VPC assets that need to make outbound connections to the internet, these can be made outbound only (one-way) through an AWS managed NAT gateway, outbound only internet gateway, or web proxies that you create and manage.",
			"Attributes": [
			  {
				"Name": "SEC05-BP02 Control traffic at all layers",
				"WellArchitectedQuestionId": "network-protection",
				"WellArchitectedPracticeId": "sec_network_protection_layered",
				"Section": "Infrastructure protection",
				"SubSection": "Protecting networks",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "When architecting your network topology, you should examine the connectivity requirements of each component. For example, if a component requires internet accessibility (inbound and outbound), connectivity to VPCs, edge services, and external data centers. A VPC allows you to define your network topology that spans an AWS Region with a private IPv4 address range that you set, or an IPv6 address range AWS selects. You should apply multiple controls with a defense in depth approach for both inbound and outbound traffic, including the use of security groups (stateful inspection firewall), Network ACLs, subnets, and route tables. Within a VPC, you can create subnets in an Availability Zone. Each subnet can have an associated route table that defines routing rules for managing the paths that traffic takes within the subnet. You can define an internet routable subnet by having a route that goes to an internet or NAT gateway attached to the VPC, or through another VPC. When an instance, Amazon Relational Database Service(Amazon RDS) database, or other service is launched within a VPC, it has its own security group per network interface. This firewall is outside the operating system layer and can be used to define rules for allowed inbound and outbound traffic. You can also define relationships between security groups. For example, instances within a database tier security group only accept traffic from instances within the application tier, by reference to the security groups applied to the instances involved. Unless you are using non-TCP protocols, it shouldn't be necessary to have an Amazon Elastic Compute Cloud(Amazon EC2) instance directly accessible by the internet (even with ports restricted by security groups) without a load balancer, or CloudFront. This helps protect it from unintended access through an operating system or application issue. A subnet can also have a network ACL attached to it, which acts as a stateless firewall. You should configure the network ACL to narrow the scope of traffic allowed between layers, note that you need to define both inbound and outbound rules. Some AWS services require components to access the internet for making API calls, where AWS API endpoints are located. Other AWS services use VPC endpoints within your Amazon VPCs. Many AWS services, including Amazon S3 and Amazon DynamoDB, support VPC endpoints, and this technology has been generalized in AWS PrivateLink. We recommend you use this approach to access AWS services, third-party services, and your own services hosted in other VPCs securely. All network traffic on AWS PrivateLink stays on the global AWS backbone and never traverses the internet. Connectivity can only be initiated by the consumer of the service, and not by the provider of the service. Using AWS PrivateLink for external service access allows you to create air-gapped VPCs with no internet access and helps protect your VPCs from external threat vectors. Third-party services can use AWS PrivateLink to allow their customers to connect to the services from their VPCs over private IP addresses. For VPC assets that need to make outbound connections to the internet, these can be made outbound only (one-way) through an AWS managed NAT gateway, outbound only internet gateway, or web proxies that you create and manage.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_network_protection_layered.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "ec2_ebs_public_snapshot",
			  "ec2_networkacl_allow_ingress_tcp_port_22",
			  "sagemaker_notebook_instance_without_direct_internet_access_configured",
			  "apigateway_restapi_authorizers_enabled",
			  "apigatewayv2_api_authorizers_enabled",
			  "s3_bucket_acl_prohibited",
			  "s3_bucket_no_mfa_delete"
			]
		  },
		  {
			"Id": "SEC05-BP03",
			"Description": "Automate protection mechanisms to provide a self-defending network based on threat intelligence and anomaly detection. For example, intrusion detection and prevention tools that can adapt to current threats and reduce their impact. A web application firewall is an example of where you can automate network protection, for example, by using the AWS WAF Security Automations solution (https://github.com/awslabs/aws-waf-security-automations) to automatically block requests originating from IP addresses associated with known threat actors.",
			"Attributes": [
			  {
				"Name": "SEC05-BP03 Automate network protections",
				"WellArchitectedQuestionId": "network-protection",
				"WellArchitectedPracticeId": "sec_network_protection_auto_protect",
				"Section": "Infrastructure protection",
				"SubSection": "Protecting networks",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Automate protection mechanisms to provide a self-defending network based on threat intelligence and anomaly detection. For example, intrusion detection and prevention tools that can adapt to current threats and reduce their impact. A web application firewall is an example of where you can automate network protection, for example, by using the AWS WAF Security Automations solution (https://github.com/awslabs/aws-waf-security-automations) to automatically block requests originating from IP addresses associated with known threat actors.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_network_protection_auto_protect.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "ec2_networkacl_allow_ingress_any_port",
			  "ec2_networkacl_allow_ingress_tcp_port_22",
			  "ec2_networkacl_allow_ingress_tcp_port_3389",
			  "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
			  "ec2_securitygroup_allow_ingress_from_internet_to_port_mongodb_27017_27018",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_ftp_port_20_21",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23",
			  "elbv2_waf_acl_attached",
			  "ec2_securitygroup_default_restrict_traffic",
			  "ec2_securitygroup_from_launch_wizard",
			  "ec2_securitygroup_not_used",
			  "ec2_securitygroup_with_many_ingress_egress_rules",
			  "elbv2_desync_mitigation_mode",
			  "elbv2_desync_mitigation_mode",
			  "route53_domains_privacy_protection_enabled",
			  "route53_domains_transferlock_enabled",
			  "shield_advanced_protection_in_associated_elastic_ips",
			  "shield_advanced_protection_in_classic_load_balancers",
			  "shield_advanced_protection_in_cloudfront_distributions",
			  "shield_advanced_protection_in_global_accelerators",
			  "shield_advanced_protection_in_internet_facing_load_balancers",
			  "shield_advanced_protection_in_route53_hosted_zones"
			]
		  },
		  {
			"Id": "SEC05-BP04",
			"Description": "Inspect and filter your traffic at each layer. You can inspect your VPC configurations for potential unintended access using VPC Network Access Analyzer. You can specify your network access requirements and identify potential network paths that do not meet them. For components transacting over HTTP-based protocols, a web application firewall can help protect from common attacks. AWS WAF is a web application firewall that lets you monitor and block HTTP(s) requests that match your configurable rules that are forwarded to an Amazon API Gateway API, Amazon CloudFront, or an Application Load Balancer. To get started with AWS WAF, you can use AWS Managed Rules in combination with your own, or use existing partner integrations. For managing AWS WAF, AWS Shield Advanced protections, and Amazon VPC security groups across AWS Organizations, you can use AWS Firewall Manager. It allows you to centrally configure and manage firewall rules across your accounts and applications, making it easier to scale enforcement of common rules. It also enables you to rapidly respond to attacks, using AWS Shield Advanced, or solutions that can automatically block unwanted requests to your web applications. Firewall Manager also works with AWS Network Firewall. AWS Network Firewall is a managed service that uses a rules engine to give you fine-grained control over both stateful and stateless network traffic. It supports the Suricata compatible open source intrusion prevention system (IPS) specifications for rules to help protect your workload.",
			"Attributes": [
			  {
				"Name": "SEC05-BP04 Implement inspection and protection",
				"WellArchitectedQuestionId": "network-protection",
				"WellArchitectedPracticeId": "sec_network_protection_inspection",
				"Section": "Infrastructure protection",
				"SubSection": "Protecting networks",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Inspect and filter your traffic at each layer. You can inspect your VPC configurations for potential unintended access using VPC Network Access Analyzer. You can specify your network access requirements and identify potential network paths that do not meet them. For components transacting over HTTP-based protocols, a web application firewall can help protect from common attacks. AWS WAF is a web application firewall that lets you monitor and block HTTP(s) requests that match your configurable rules that are forwarded to an Amazon API Gateway API, Amazon CloudFront, or an Application Load Balancer. To get started with AWS WAF, you can use AWS Managed Rules in combination with your own, or use existing partner integrations. For managing AWS WAF, AWS Shield Advanced protections, and Amazon VPC security groups across AWS Organizations, you can use AWS Firewall Manager. It allows you to centrally configure and manage firewall rules across your accounts and applications, making it easier to scale enforcement of common rules. It also enables you to rapidly respond to attacks, using AWS Shield Advanced, or solutions that can automatically block unwanted requests to your web applications. Firewall Manager also works with AWS Network Firewall. AWS Network Firewall is a managed service that uses a rules engine to give you fine-grained control over both stateful and stateless network traffic. It supports the Suricata compatible open source intrusion prevention system (IPS) specifications for rules to help protect your workload.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_network_protection_inspection.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "guardduty_is_enabled",
			  "vpc_flow_logs_enabled",
			  "apigateway_restapi_authorizers_enabled"
			]
		  },
		  {
			"Id": "SEC06-BP01",
			"Description": "Frequently scan and patch for vulnerabilities in your code, dependencies, and in your infrastructure to help protect against new threats. Starting with the configuration of your compute infrastructure, you can automate creating and updating resources using AWS CloudFormation. CloudFormation allows you to create templates written in YAML or JSON, either using AWS examples or by writing your own. This allows you to create secure-by-default infrastructure templates that you can verify with CloudFormation Guard, to save you time and reduce the risk of configuration error. You can build your infrastructure and deploy your applications using continuous delivery, for example with AWS CodePipeline, to automate the building, testing, and release. You are responsible for patch management for your AWS resources, including Amazon Elastic Compute Cloud(Amazon EC2) instances, Amazon Machine Images (AMIs), and many other compute resources. For Amazon EC2 instances, AWS Systems Manager Patch Manager automates the process of patching managed instances with both security related and other types of updates. You can use Patch Manager to apply patches for both operating systems and applications. (On Windows Server, application support is limited to updates for Microsoft applications.) You can use Patch Manager to install Service Packs on Windows instances and perform minor version upgrades on Linux instances. You can patch fleets of Amazon EC2 instances or your on-premises servers and virtual machines (VMs) by operating system type. This includes supported versions of Windows Server, Amazon Linux, Amazon Linux 2, CentOS, Debian Server, Oracle Linux, Red Hat Enterprise Linux (RHEL), SUSE Linux Enterprise Server (SLES), and Ubuntu Server. You can scan instances to see only a report of missing patches, or you can scan and automatically install all missing patches.",
			"Attributes": [
			  {
				"Name": "SEC06-BP01 Perform vulnerability management",
				"WellArchitectedQuestionId": "protect-compute",
				"WellArchitectedPracticeId": "sec_protect_compute_vulnerability_management",
				"Section": "Infrastructure protection",
				"SubSection": "Protecting compute",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Frequently scan and patch for vulnerabilities in your code, dependencies, and in your infrastructure to help protect against new threats. Starting with the configuration of your compute infrastructure, you can automate creating and updating resources using AWS CloudFormation. CloudFormation allows you to create templates written in YAML or JSON, either using AWS examples or by writing your own. This allows you to create secure-by-default infrastructure templates that you can verify with CloudFormation Guard, to save you time and reduce the risk of configuration error. You can build your infrastructure and deploy your applications using continuous delivery, for example with AWS CodePipeline, to automate the building, testing, and release. You are responsible for patch management for your AWS resources, including Amazon Elastic Compute Cloud(Amazon EC2) instances, Amazon Machine Images (AMIs), and many other compute resources. For Amazon EC2 instances, AWS Systems Manager Patch Manager automates the process of patching managed instances with both security related and other types of updates. You can use Patch Manager to apply patches for both operating systems and applications. (On Windows Server, application support is limited to updates for Microsoft applications.) You can use Patch Manager to install Service Packs on Windows instances and perform minor version upgrades on Linux instances. You can patch fleets of Amazon EC2 instances or your on-premises servers and virtual machines (VMs) by operating system type. This includes supported versions of Windows Server, Amazon Linux, Amazon Linux 2, CentOS, Debian Server, Oracle Linux, Red Hat Enterprise Linux (RHEL), SUSE Linux Enterprise Server (SLES), and Ubuntu Server. You can scan instances to see only a report of missing patches, or you can scan and automatically install all missing patches.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_network_protection_inspection.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "rds_instance_minor_version_upgrade_enabled",
			  "cloudtrail_log_file_validation_enabled",
			  "ec2_instance_imdsv2_enabled",
			  "ec2_instance_internet_facing_with_instance_profile",
			  "opensearch_service_domains_updated_to_the_latest_service_software_version",
			  "redshift_cluster_automatic_upgrades",
			  "ssm_managed_compliant_patching"
			]
		  },
		  {
			"Id": "SEC06-BP02",
			"Description": "Reduce your exposure to unintended access by hardening operating systems and minimizing the components, libraries, and externally consumable services in use. Start by reducing unused components, whether they are operating system packages or applications, for Amazon Elastic Compute Cloud (Amazon EC2)-based workloads, or external software modules in your code, for all workloads. You can find many hardening and security configuration guides for common operating systems and server software. For example, you can start with the Center for Internet Security and iterate.In Amazon EC2, you can create your own Amazon Machine Images (AMIs), which you have patched and hardened, to help you meet the specific security requirements for your organization. The patches and other security controls you apply on the AMI are effective at the point in time in which they were created—they are not dynamic unless you modify after launching, for example, with AWS Systems Manager.You can simplify the process of building secure AMIs with EC2 Image Builder. EC2 Image Builder significantly reduces the effort required to create and maintain golden images without writing and maintaining automation. When software updates become available, Image Builder automatically produces a new image without requiring users to manually initiate image builds. EC2 Image Builder allows you to easily validate the functionality and security of your images before using them in production with AWS-provided tests and your own tests. You can also apply AWS-provided security settings to further secure your images to meet internal security criteria. For example, you can produce images that conform to the Security Technical Implementation Guide (STIG) standard using AWS-provided templates.Using third-party static code analysis tools, you can identify common security issues such as unchecked function input bounds, as well as applicable common vulnerabilities and exposures (CVEs). You can use Amazon CodeGuru for supported languages. Dependency checking tools can also be used to determine whether libraries your code links against are the latest versions, are themselves free of CVEs, and have licensing conditions that meet your software policy requirements.Using Amazon Inspector, you can perform configuration assessments against your instances for known CVEs, assess against security benchmarks, and automate the notification of defects. Amazon Inspector runs on production instances or in a build pipeline, and it notifies developers and engineers when findings are present. You can access findings programmatically and direct your team to backlogs and bug-tracking systems. EC2 Image Builder can be used to maintain server images (AMIs) with automated patching, AWS-provided security policy enforcement, and other customizations. When using containers implement ECR Image Scanning in your build pipeline and on a regular basis against your image repository to look for CVEs in your containers.While Amazon Inspector and other tools are effective at identifying configurations and any CVEs that are present, other methods are required to test your workload at the application level. Fuzzing is a well-known method of finding bugs using automation to inject malformed data into input fields and other areas of your application.",
			"Attributes": [
			  {
				"Name": "SEC06-BP02 Reduce attack surface",
				"WellArchitectedQuestionId": "protect-compute",
				"WellArchitectedPracticeId": "sec_protect_compute_reduce_surface",
				"Section": "Infrastructure protection",
				"SubSection": "Protecting compute",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Reduce your exposure to unintended access by hardening operating systems and minimizing the components, libraries, and externally consumable services in use. Start by reducing unused components, whether they are operating system packages or applications, for Amazon Elastic Compute Cloud (Amazon EC2)-based workloads, or external software modules in your code, for all workloads. You can find many hardening and security configuration guides for common operating systems and server software. For example, you can start with the Center for Internet Security and iterate.In Amazon EC2, you can create your own Amazon Machine Images (AMIs), which you have patched and hardened, to help you meet the specific security requirements for your organization. The patches and other security controls you apply on the AMI are effective at the point in time in which they were created—they are not dynamic unless you modify after launching, for example, with AWS Systems Manager.You can simplify the process of building secure AMIs with EC2 Image Builder. EC2 Image Builder significantly reduces the effort required to create and maintain golden images without writing and maintaining automation. When software updates become available, Image Builder automatically produces a new image without requiring users to manually initiate image builds. EC2 Image Builder allows you to easily validate the functionality and security of your images before using them in production with AWS-provided tests and your own tests. You can also apply AWS-provided security settings to further secure your images to meet internal security criteria. For example, you can produce images that conform to the Security Technical Implementation Guide (STIG) standard using AWS-provided templates.Using third-party static code analysis tools, you can identify common security issues such as unchecked function input bounds, as well as applicable common vulnerabilities and exposures (CVEs). You can use Amazon CodeGuru for supported languages. Dependency checking tools can also be used to determine whether libraries your code links against are the latest versions, are themselves free of CVEs, and have licensing conditions that meet your software policy requirements.Using Amazon Inspector, you can perform configuration assessments against your instances for known CVEs, assess against security benchmarks, and automate the notification of defects. Amazon Inspector runs on production instances or in a build pipeline, and it notifies developers and engineers when findings are present. You can access findings programmatically and direct your team to backlogs and bug-tracking systems. EC2 Image Builder can be used to maintain server images (AMIs) with automated patching, AWS-provided security policy enforcement, and other customizations. When using containers implement ECR Image Scanning in your build pipeline and on a regular basis against your image repository to look for CVEs in your containers.While Amazon Inspector and other tools are effective at identifying configurations and any CVEs that are present, other methods are required to test your workload at the application level. Fuzzing is a well-known method of finding bugs using automation to inject malformed data into input fields and other areas of your application.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_compute_reduce_surface.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "awslambda_function_not_publicly_accessible",
			  "ecr_repositories_scan_images_on_push_enabled"
			]
		  },
		  {
			"Id": "SEC06-BP03",
			"Description": "Implement services that manage resources, such as Amazon Relational Database Service (Amazon RDS), AWS Lambda, and Amazon Elastic Container Service (Amazon ECS), to reduce your security maintenance tasks as part of the shared responsibility model. For example, Amazon RDS helps you set up, operate, and scale a relational database, automates administration tasks such as hardware provisioning, database setup, patching, and backups. This means you have more free time to focus on securing your application in other ways described in the AWS Well-Architected Framework. Lambda lets you run code without provisioning or managing servers, so you only need to focus on the connectivity, invocation, and security at the code level–not the infrastructure or operating system.",
			"Attributes": [
			  {
				"Name": "SEC06-BP03 Implement managed services",
				"WellArchitectedQuestionId": "protect-compute",
				"WellArchitectedPracticeId": "sec_protect_compute_implement_managed_services",
				"Section": "Infrastructure protection",
				"SubSection": "Protecting compute",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Implement services that manage resources, such as Amazon Relational Database Service (Amazon RDS), AWS Lambda, and Amazon Elastic Container Service (Amazon ECS), to reduce your security maintenance tasks as part of the shared responsibility model. For example, Amazon RDS helps you set up, operate, and scale a relational database, automates administration tasks such as hardware provisioning, database setup, patching, and backups. This means you have more free time to focus on securing your application in other ways described in the AWS Well-Architected Framework. Lambda lets you run code without provisioning or managing servers, so you only need to focus on the connectivity, invocation, and security at the code level–not the infrastructure or operating system.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_compute_implement_managed_services.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC06-BP04",
			"Description": "Automate your protective compute mechanisms including vulnerability management, reduction in attack surface, and management of resources. The automation will help you invest time in securing other aspects of your workload, and reduce the risk of human error.",
			"Attributes": [
			  {
				"Name": "SEC06-BP04 Automate compute protection",
				"WellArchitectedQuestionId": "protect-compute",
				"WellArchitectedPracticeId": "sec_protect_compute_auto_protection",
				"Section": "Infrastructure protection",
				"SubSection": "Protecting compute",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Automate your protective compute mechanisms including vulnerability management, reduction in attack surface, and management of resources. The automation will help you invest time in securing other aspects of your workload, and reduce the risk of human error.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_compute_auto_protection.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "ec2_instance_profile_attached",
			  "ec2_instance_managed_by_ssm"
			]
		  },
		  {
			"Id": "SEC06-BP05",
			"Description": "Removing the ability for interactive access reduces the risk of human error, and the potential for manual configuration or management. For example, use a change management workflow to deploy Amazon Elastic Compute Cloud (Amazon EC2) instances using infrastructure-as-code, then manage Amazon EC2 instances using tools such as AWS Systems Manager instead of allowing direct access or through a bastion host. AWS Systems Manager can automate a variety of maintenance and deployment tasks, using features including automation workflows, documents (playbooks), and the run command. AWS CloudFormation stacks build from pipelines and can automate your infrastructure deployment and management tasks without using the AWS Management Console or APIs directly.",
			"Attributes": [
			  {
				"Name": "SEC06-BP05 Enable people to perform actions at a distance",
				"WellArchitectedQuestionId": "protect-compute",
				"WellArchitectedPracticeId": "sec_protect_compute_actions_distance",
				"Section": "Infrastructure protection",
				"SubSection": "Protecting compute",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Removing the ability for interactive access reduces the risk of human error, and the potential for manual configuration or management. For example, use a change management workflow to deploy Amazon Elastic Compute Cloud (Amazon EC2) instances using infrastructure-as-code, then manage Amazon EC2 instances using tools such as AWS Systems Manager instead of allowing direct access or through a bastion host. AWS Systems Manager can automate a variety of maintenance and deployment tasks, using features including automation workflows, documents (playbooks), and the run command. AWS CloudFormation stacks build from pipelines and can automate your infrastructure deployment and management tasks without using the AWS Management Console or APIs directly.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_compute_actions_distance.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "ec2_instance_profile_attached",
			  "ec2_instance_managed_by_ssm"
			]
		  },
		  {
			"Id": "SEC06-BP06",
			"Description": "Implement mechanisms (for example, code signing) to validate that the software, code and libraries used in the workload are from trusted sources and have not been tampered with. For example, you should verify the code signing certificate of binaries and scripts to confirm the author, and ensure it has not been tampered with since created by the author. AWS Signer can help ensure the trust and integrity of your code by centrally managing the code- signing lifecycle, including signing certification and public and private keys. You can learn how to use advanced patterns and best practices for code signing with AWS Lambda. Additionally, a checksum of software that you download, compared to that of the checksum from the provider, can help ensure it has not been tampered with.",
			"Attributes": [
			  {
				"Name": "SEC06-BP06 Validate software integrity",
				"WellArchitectedQuestionId": "protect-compute",
				"WellArchitectedPracticeId": "sec_protect_compute_validate_software_integrity",
				"Section": "Infrastructure protection",
				"SubSection": "Protecting compute",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Implement mechanisms (for example, code signing) to validate that the software, code and libraries used in the workload are from trusted sources and have not been tampered with. For example, you should verify the code signing certificate of binaries and scripts to confirm the author, and ensure it has not been tampered with since created by the author. AWS Signer can help ensure the trust and integrity of your code by centrally managing the code- signing lifecycle, including signing certification and public and private keys. You can learn how to use advanced patterns and best practices for code signing with AWS Lambda. Additionally, a checksum of software that you download, compared to that of the checksum from the provider, can help ensure it has not been tampered with.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_compute_validate_software_integrity.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "cloudtrail_log_file_validation_enabled"
			]
		  },
		  {
			"Id": "SEC07-BP01",
			"Description": "It’s critical to understand the type and classification of data your workload is processing, the associated business processes, where the data is stored, and who is the data owner. You should also have an understanding of the applicable legal and compliance requirements of your workload, and what data controls need to be enforced. Identifying data is the first step in the data classification journey.",
			"Attributes": [
			  {
				"Name": "SEC07-BP01 Identify the data within your workload",
				"WellArchitectedQuestionId": "data-classification",
				"WellArchitectedPracticeId": "sec_data_classification_identify_data",
				"Section": "Data protection",
				"SubSection": "Data classification",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "It’s critical to understand the type and classification of data your workload is processing, the associated business processes, where the data is stored, and who is the data owner. You should also have an understanding of the applicable legal and compliance requirements of your workload, and what data controls need to be enforced. Identifying data is the first step in the data classification journey.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_data_classification_identify_data.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC07-BP02",
			"Description": "Protect data according to its classification level. For example, secure data classified as public by using relevant recommendations while protecting sensitive data with additional controls.By using resource tags, separate AWS accounts per sensitivity (and potentially also for each caveat, enclave, or community of interest), IAM policies, AWS Organizations SCPs, AWS Key Management Service (AWS KMS), and AWS CloudHSM, you can define and implement your policies for data classification and protection with encryption. For example, if you have a project with S3 buckets that contain highly critical data or Amazon Elastic Compute Cloud (Amazon EC2) instances that process confidential data, they can be tagged with a Project=ABC tag. Only your immediate team knows what the project code means, and it provides a way to use attribute-based access control. You can define levels of access to the AWS KMS encryption keys through key policies and grants to ensure that only appropriate services have access to the sensitive content through a secure mechanism. If you are making authorization decisions based on tags you should make sure that the permissions on the tags are defined appropriately using tag policies in AWS Organizations.",
			"Attributes": [
			  {
				"Name": "SEC07-BP02 Define data protection controls",
				"WellArchitectedQuestionId": "data-classification",
				"WellArchitectedPracticeId": "sec_data_classification_define_protection",
				"Section": "Data protection",
				"SubSection": "Data classification",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Protect data according to its classification level. For example, secure data classified as public by using relevant recommendations while protecting sensitive data with additional controls.By using resource tags, separate AWS accounts per sensitivity (and potentially also for each caveat, enclave, or community of interest), IAM policies, AWS Organizations SCPs, AWS Key Management Service (AWS KMS), and AWS CloudHSM, you can define and implement your policies for data classification and protection with encryption. For example, if you have a project with S3 buckets that contain highly critical data or Amazon Elastic Compute Cloud (Amazon EC2) instances that process confidential data, they can be tagged with a Project=ABC tag. Only your immediate team knows what the project code means, and it provides a way to use attribute-based access control. You can define levels of access to the AWS KMS encryption keys through key policies and grants to ensure that only appropriate services have access to the sensitive content through a secure mechanism. If you are making authorization decisions based on tags you should make sure that the permissions on the tags are defined appropriately using tag policies in AWS Organizations.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_data_classification_define_protection.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC07-BP03",
			"Description": "Automating the identification and classification of data can help you implement the correct controls. Using automation for this instead of direct access from a person reduces the risk of human error and exposure. You should evaluate using a tool, such as Amazon Macie, that uses machine learning to automatically discover, classify, and protect sensitive data in AWS. Amazon Macie recognizes sensitive data, such as personally identifiable information (PII) or intellectual property, and provides you with dashboards and alerts that give visibility into how this data is being accessed or moved.",
			"Attributes": [
			  {
				"Name": "SEC07-BP03 Automate identification and classification",
				"WellArchitectedQuestionId": "data-classification",
				"WellArchitectedPracticeId": "sec_data_classification_auto_classification",
				"Section": "Data protection",
				"SubSection": "Data classification",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Automating the identification and classification of data can help you implement the correct controls. Using automation for this instead of direct access from a person reduces the risk of human error and exposure. You should evaluate using a tool, such as Amazon Macie, that uses machine learning to automatically discover, classify, and protect sensitive data in AWS. Amazon Macie recognizes sensitive data, such as personally identifiable information (PII) or intellectual property, and provides you with dashboards and alerts that give visibility into how this data is being accessed or moved.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_data_classification_auto_classification.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC07-BP04",
			"Description": "Your defined lifecycle strategy should be based on sensitivity level as well as legal and organization requirements. Aspects including the duration for which you retain data, data destruction processes, data access management, data transformation, and data sharing should be considered. When choosing a data classification methodology, balance usability versus access. You should also accommodate the multiple levels of access and nuances for implementing a secure, but still usable, approach for each level. Always use a defense in depth approach and reduce human access to data and mechanisms for transforming, deleting, or copying data. For example, require users to strongly authenticate to an application, and give the application, rather than the users, the requisite access permission to perform action at a distance. In addition, ensure that users come from a trusted network path and require access to the decryption keys. Use tools, such as dashboards and automated reporting, to give users information from the data rather than giving them direct access to the data.",
			"Attributes": [
			  {
				"Name": "SEC07-BP04 Define data lifecycle management",
				"WellArchitectedQuestionId": "data-classification",
				"WellArchitectedPracticeId": "sec_data_classification_lifecycle_management",
				"Section": "Data protection",
				"SubSection": "Data classification",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Your defined lifecycle strategy should be based on sensitivity level as well as legal and organization requirements. Aspects including the duration for which you retain data, data destruction processes, data access management, data transformation, and data sharing should be considered. When choosing a data classification methodology, balance usability versus access. You should also accommodate the multiple levels of access and nuances for implementing a secure, but still usable, approach for each level. Always use a defense in depth approach and reduce human access to data and mechanisms for transforming, deleting, or copying data. For example, require users to strongly authenticate to an application, and give the application, rather than the users, the requisite access permission to perform action at a distance. In addition, ensure that users come from a trusted network path and require access to the decryption keys. Use tools, such as dashboards and automated reporting, to give users information from the data rather than giving them direct access to the data.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_data_classification_lifecycle_management.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC08-BP01",
			"Description": "By defining an encryption approach that includes the storage, rotation, and access control of keys, you can help provide protection for your content against unauthorized users and against unnecessary exposure to authorized users. AWS Key Management Service (AWS KMS) helps you manage encryption keys and integrates with many AWS services. This service provides durable, secure, and redundant storage for your AWS KMS keys. You can define your key aliases as well as key-level policies. The policies help you define key administrators as well as key users. Additionally, AWS CloudHSM is a cloud-based hardware security module (HSM) that enables you to easily generate and use your own encryption keys in the AWS Cloud. It helps you meet corporate, contractual, and regulatory compliance requirements for data security by using FIPS 140-2 Level 3 validated HSMs.",
			"Attributes": [
			  {
				"Name": "SEC08-BP01 Implement secure key management",
				"WellArchitectedQuestionId": "protect-data-rest",
				"WellArchitectedPracticeId": "sec_protect_data_rest_key_mgmt",
				"Section": "Data protection",
				"SubSection": "Protecting data at rest",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "By defining an encryption approach that includes the storage, rotation, and access control of keys, you can help provide protection for your content against unauthorized users and against unnecessary exposure to authorized users. AWS Key Management Service (AWS KMS) helps you manage encryption keys and integrates with many AWS services. This service provides durable, secure, and redundant storage for your AWS KMS keys. You can define your key aliases as well as key-level policies. The policies help you define key administrators as well as key users. Additionally, AWS CloudHSM is a cloud-based hardware security module (HSM) that enables you to easily generate and use your own encryption keys in the AWS Cloud. It helps you meet corporate, contractual, and regulatory compliance requirements for data security by using FIPS 140-2 Level 3 validated HSMs.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_rest_key_mgmt.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "kms_cmk_are_used"
			]
		  },
		  {
			"Id": "SEC08-BP02",
			"Description": "You should ensure that the only way to store data is by using encryption. AWS Key Management Service (AWS KMS) integrates seamlessly with many AWS services to make it easier for you to encrypt all your data at rest. For example, in Amazon Simple Storage Service (Amazon S3), you can set default encryption on a bucket so that all new objects are automatically encrypted. Additionally, Amazon Elastic Compute Cloud (Amazon EC2) and Amazon S3 support the enforcement of encryption by setting default encryption. You can use AWS Config Rules to check automatically that you are using encryption, for example, for Amazon Elastic Block Store (Amazon EBS) volumes, Amazon Relational Database Service (Amazon RDS) instances, and Amazon S3 buckets.",
			"Attributes": [
			  {
				"Name": "SEC08-BP02 Enforce encryption at rest",
				"WellArchitectedQuestionId": "protect-data-rest",
				"WellArchitectedPracticeId": "sec_protect_data_rest_encrypt",
				"Section": "Data protection",
				"SubSection": "Protecting data at rest",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "You should ensure that the only way to store data is by using encryption. AWS Key Management Service (AWS KMS) integrates seamlessly with many AWS services to make it easier for you to encrypt all your data at rest. For example, in Amazon Simple Storage Service (Amazon S3), you can set default encryption on a bucket so that all new objects are automatically encrypted. Additionally, Amazon Elastic Compute Cloud (Amazon EC2) and Amazon S3 support the enforcement of encryption by setting default encryption. You can use AWS Config Rules to check automatically that you are using encryption, for example, for Amazon Elastic Block Store (Amazon EBS) volumes, Amazon Relational Database Service (Amazon RDS) instances, and Amazon S3 buckets.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_rest_encrypt.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "efs_encryption_at_rest_enabled",
			  "opensearch_service_domains_encryption_at_rest_enabled",
			  "ec2_ebs_volume_encryption",
			  "rds_instance_storage_encrypted",
			  "cloudtrail_kms_encryption_enabled",
			  "cloudwatch_log_group_kms_encryption_enabled",
			  "dynamodb_accelerator_cluster_encryption_enabled",
			  "dynamodb_tables_kms_cmk_encryption_enabled",
			  "ec2_ebs_default_encryption",
			  "ec2_ebs_snapshots_encrypted",
			  "eks_cluster_kms_cmk_encryption_in_secrets_enabled",
			  "glue_data_catalogs_connection_passwords_encryption_enabled",
			  "glue_data_catalogs_metadata_encryption_enabled",
			  "glue_database_connections_ssl_enabled",
			  "glue_development_endpoints_cloudwatch_logs_encryption_enabled",
			  "glue_development_endpoints_job_bookmark_encryption_enabled",
			  "glue_development_endpoints_s3_encryption_enabled",
			  "glue_etl_jobs_amazon_s3_encryption_enabled",
			  "glue_etl_jobs_cloudwatch_logs_encryption_enabled",
			  "glue_etl_jobs_job_bookmark_encryption_enabled",
			  "sagemaker_notebook_instance_encryption_enabled",
			  "sagemaker_training_jobs_intercontainer_encryption_enabled",
			  "sagemaker_training_jobs_volume_and_output_encryption_enabled",
			  "sqs_queues_server_side_encryption_enabled",
			  "workspaces_volume_encryption_enabled"
			]
		  },
		  {
			"Id": "SEC08-BP03",
			"Description": "Use automated tools to validate and enforce data at rest controls continuously, for example, verify that there are only encrypted storage resources. You can automate validation that all EBS volumes are encrypted using AWS Config Rules. AWS Security Hub can also verify several different controls through automated checks against security standards. Additionally, your AWS Config Rules can automatically remediate noncompliant resources.",
			"Attributes": [
			  {
				"Name": "SEC08-BP03 Automate data at rest protection",
				"WellArchitectedQuestionId": "protect-data-rest",
				"WellArchitectedPracticeId": "sec_protect_data_rest_automate_protection",
				"Section": "Data protection",
				"SubSection": "Protecting data at rest",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Use automated tools to validate and enforce data at rest controls continuously, for example, verify that there are only encrypted storage resources. You can automate validation that all EBS volumes are encrypted using AWS Config Rules. AWS Security Hub can also verify several different controls through automated checks against security standards. Additionally, your AWS Config Rules can automatically remediate noncompliant resources.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_rest_automate_protection.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "s3_bucket_default_encryption",
			  "sagemaker_notebook_instance_encryption_enabled"
			]
		  },
		  {
			"Id": "SEC08-BP04",
			"Description": "To help protect your data at rest, enforce access control using mechanisms, such as isolation and versioning, and apply the principle of least privilege. Prevent the granting of public access to your data.",
			"Attributes": [
			  {
				"Name": "SEC08-BP04 Enforce access control",
				"WellArchitectedQuestionId": "protect-data-rest",
				"WellArchitectedPracticeId": "sec_protect_data_rest_access_control",
				"Section": "Data protection",
				"SubSection": "Protecting data at rest",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "To help protect your data at rest, enforce access control using mechanisms, such as isolation and versioning, and apply the principle of least privilege. Prevent the granting of public access to your data.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_rest_access_control.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "sns_topics_kms_encryption_at_rest_enabled",
			  "s3_bucket_object_versioning",
			  "organizations_account_part_of_organizations"
			]
		  },
		  {
			"Id": "SEC08-BP05",
			"Description": "Keep all users away from directly accessing sensitive data and systems under normal operational circumstances. For example, use a change management workflow to manage Amazon Elastic Compute Cloud (Amazon EC2) instances using tools instead of allowing direct access or a bastion host. This can be achieved using AWS Systems Manager Automation, which uses automation documents that contain steps you use to perform tasks. These documents can be stored in source control, be peer reviewed before running, and tested thoroughly to minimize risk compared to shell access. Business users could have a dashboard instead of direct access to a data store to run queries. Where CI/CD pipelines are not used, determine which controls and processes are required to adequately provide a normally disabled break-glass access mechanism.",
			"Attributes": [
			  {
				"Name": "SEC08-BP05 Use mechanisms to keep people away from data",
				"WellArchitectedQuestionId": "protect-data-rest",
				"WellArchitectedPracticeId": "sec_protect_data_rest_use_people_away",
				"Section": "Data protection",
				"SubSection": "Protecting data at rest",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Keep all users away from directly accessing sensitive data and systems under normal operational circumstances. For example, use a change management workflow to manage Amazon Elastic Compute Cloud (Amazon EC2) instances using tools instead of allowing direct access or a bastion host. This can be achieved using AWS Systems Manager Automation, which uses automation documents that contain steps you use to perform tasks. These documents can be stored in source control, be peer reviewed before running, and tested thoroughly to minimize risk compared to shell access. Business users could have a dashboard instead of direct access to a data store to run queries. Where CI/CD pipelines are not used, determine which controls and processes are required to adequately provide a normally disabled break-glass access mechanism.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_rest_use_people_away.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC09-BP01",
			"Description": "Store encryption keys and certificates securely and rotate them at appropriate time intervals with strict access control. The best way to accomplish this is to use a managed service, such as AWS Certificate Manager (ACM). It lets you easily provision, manage, and deploy public and private Transport Layer Security (TLS) certificates for use with AWS services and your internal connected resources. TLS certificates are used to secure network communications and establish the identity of websites over the internet as well as resources on private networks. ACM integrates with AWS resources, such as Elastic Load Balancers (ELBs), AWS distributions, and APIs on API Gateway, also handling automatic certificate renewals. If you use ACM to deploy a private root CA, both certificates and private keys can be provided by it for use in Amazon Elastic Compute Cloud (Amazon EC2) instances, containers, and so on.",
			"Attributes": [
			  {
				"Name": "SEC09-BP01 Implement secure key and certificate management",
				"WellArchitectedQuestionId": "protect-data-transit",
				"WellArchitectedPracticeId": "sec_protect_data_transit_key_cert_mgmt",
				"Section": "Data protection",
				"SubSection": "Protecting data in transit",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Store encryption keys and certificates securely and rotate them at appropriate time intervals with strict access control. The best way to accomplish this is to use a managed service, such as AWS Certificate Manager (ACM). It lets you easily provision, manage, and deploy public and private Transport Layer Security (TLS) certificates for use with AWS services and your internal connected resources. TLS certificates are used to secure network communications and establish the identity of websites over the internet as well as resources on private networks. ACM integrates with AWS resources, such as Elastic Load Balancers (ELBs), AWS distributions, and APIs on API Gateway, also handling automatic certificate renewals. If you use ACM to deploy a private root CA, both certificates and private keys can be provided by it for use in Amazon Elastic Compute Cloud (Amazon EC2) instances, containers, and so on.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_transit_key_cert_mgmt.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "acm_certificates_expiration_check",
			  "directoryservice_ldap_certificate_expiration"
			]
		  },
		  {
			"Id": "SEC09-BP02",
			"Description": "Enforce your defined encryption requirements based on appropriate standards and recommendations to help you meet your organizational, legal, and compliance requirements. AWS services provide HTTPS endpoints using TLS for communication, thus providing encryption in transit when communicating with the AWS APIs. Insecure protocols, such as HTTP, can be audited and blocked in a VPC through the use of security groups. HTTP requests can also be automatically redirected to HTTPS in Amazon CloudFront or on an Application Load Balancer. You have full control over your computing resources to implement encryption in transit across your services. Additionally, you can use VPN connectivity into your VPC from an external network to facilitate encryption of traffic. Third-party solutions are available in the AWS Marketplace, if you have special requirements.",
			"Attributes": [
			  {
				"Name": "SEC09-BP02 Enforce encryption in transit",
				"WellArchitectedQuestionId": "protect-data-transit",
				"WellArchitectedPracticeId": "sec_protect_data_transit_encrypt",
				"Section": "Data protection",
				"SubSection": "Protecting data in transit",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Enforce your defined encryption requirements based on appropriate standards and recommendations to help you meet your organizational, legal, and compliance requirements. AWS services provide HTTPS endpoints using TLS for communication, thus providing encryption in transit when communicating with the AWS APIs. Insecure protocols, such as HTTP, can be audited and blocked in a VPC through the use of security groups. HTTP requests can also be automatically redirected to HTTPS in Amazon CloudFront or on an Application Load Balancer. You have full control over your computing resources to implement encryption in transit across your services. Additionally, you can use VPN connectivity into your VPC from an external network to facilitate encryption of traffic. Third-party solutions are available in the AWS Marketplace, if you have special requirements.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_transit_encrypt.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "opensearch_service_domains_node_to_node_encryption_enabled",
			  "opensearch_service_domains_https_communications_enforced",
			  "apigateway_restapi_client_certificate_enabled",
			  "cloudfront_distributions_field_level_encryption_enabled",
			  "cloudfront_distributions_https_enabled",
			  "cloudfront_distributions_using_deprecated_ssl_protocols",
			  "elb_insecure_ssl_ciphers",
			  "elb_ssl_listeners",
			  "elbv2_insecure_ssl_ciphers",
			  "elbv2_ssl_listeners",
			  "s3_bucket_secure_transport_policy"
			]
		  },
		  {
			"Id": "SEC09-BP03",
			"Description": "Use tools such as Amazon GuardDuty to automatically detect suspicious activity or attempts to move data outside of defined boundaries. For example, GuardDuty can detect Amazon Simple Storage Service (Amazon S3) read activity that is unusual with the Exfiltration:S3/AnomalousBehavior finding. In addition to GuardDuty, Amazon VPC Flow Logs, which capture network traffic information, can be used with Amazon EventBridge to trigger detection of abnormal connections–both successful and denied. Amazon S3 Access Analyzer can help assess what data is accessible to who in your Amazon S3 buckets.",
			"Attributes": [
			  {
				"Name": "SEC09-BP03 Automate detection of unintended data access",
				"WellArchitectedQuestionId": "protect-data-transit",
				"WellArchitectedPracticeId": "sec_protect_data_transit_auto_unintended_access",
				"Section": "Data protection",
				"SubSection": "Protecting data in transit",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Use tools such as Amazon GuardDuty to automatically detect suspicious activity or attempts to move data outside of defined boundaries. For example, GuardDuty can detect Amazon Simple Storage Service (Amazon S3) read activity that is unusual with the Exfiltration:S3/AnomalousBehavior finding. In addition to GuardDuty, Amazon VPC Flow Logs, which capture network traffic information, can be used with Amazon EventBridge to trigger detection of abnormal connections–both successful and denied. Amazon S3 Access Analyzer can help assess what data is accessible to who in your Amazon S3 buckets.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_transit_auto_unintended_access.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC09-BP04",
			"Description": "Verify the identity of communications by using protocols that support authentication, such as Transport Layer Security (TLS) or IPsec. Using network protocols that support authentication, allows for trust to be established between the parties. This adds to the encryption used in the protocol to reduce the risk of communications being altered or intercepted. Common protocols that implement authentication include Transport Layer Security (TLS), which is used in many AWS services, and IPsec, which is used in AWS Virtual Private Network (AWS VPN).",
			"Attributes": [
			  {
				"Name": "SEC09-BP04 Authenticate network communications",
				"WellArchitectedQuestionId": "protect-data-transit",
				"WellArchitectedPracticeId": "sec_protect_data_transit_authentication",
				"Section": "Data protection",
				"SubSection": "Protecting data in transit",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Verify the identity of communications by using protocols that support authentication, such as Transport Layer Security (TLS) or IPsec. Using network protocols that support authentication, allows for trust to be established between the parties. This adds to the encryption used in the protocol to reduce the risk of communications being altered or intercepted. Common protocols that implement authentication include Transport Layer Security (TLS), which is used in many AWS services, and IPsec, which is used in AWS Virtual Private Network (AWS VPN).",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_transit_authentication.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "vpc_flow_logs_enabled"
			]
		  },
		  {
			"Id": "SEC10-BP01",
			"Description": "Identify internal and external personnel, resources, and legal obligations that would help your organization respond to an incident.When you define your approach to incident response in the cloud, in unison with other teams (such as your legal counsel, leadership, business stakeholders, AWS Support Services, and others), you must identify key personnel, stakeholders, and relevant contacts. To reduce dependency and decrease response time, make sure that your team, specialist security teams, and responders are educated about the services that you use and have opportunities to practice hands-on.We encourage you to identify external AWS security partners that can provide you with outside expertise and a different perspective to augment your response capabilities. Your trusted security partners can help you identify potential risks or threats that you might not be familiar with.",
			"Attributes": [
			  {
				"Name": "SEC10-BP01 Identify key personnel and external resources",
				"WellArchitectedQuestionId": "incident-response",
				"WellArchitectedPracticeId": "sec_incident_response_identify_personnel",
				"Section": "Incident response",
				"SubSection": "Prepare",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Identify internal and external personnel, resources, and legal obligations that would help your organization respond to an incident.When you define your approach to incident response in the cloud, in unison with other teams (such as your legal counsel, leadership, business stakeholders, AWS Support Services, and others), you must identify key personnel, stakeholders, and relevant contacts. To reduce dependency and decrease response time, make sure that your team, specialist security teams, and responders are educated about the services that you use and have opportunities to practice hands-on.We encourage you to identify external AWS security partners that can provide you with outside expertise and a different perspective to augment your response capabilities. Your trusted security partners can help you identify potential risks or threats that you might not be familiar with.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_identify_personnel.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "account_maintain_current_contact_details",
			  "account_security_contact_information_is_registered",
			  "account_security_questions_are_registered_in_the_aws_account",
			  "iam_support_role_created"
			]
		  },
		  {
			"Id": "SEC10-BP02",
			"Description": "Create plans to help you respond to, communicate during, and recover from an incident. For example, you can start an incident response plan with the most likely scenarios for your workload and organization. Include how you would communicate and escalate both internally and externally.",
			"Attributes": [
			  {
				"Name": "SEC10-BP02 Develop incident management plans",
				"WellArchitectedQuestionId": "incident-response",
				"WellArchitectedPracticeId": "sec_incident_response_develop_management_plans",
				"Section": "Incident response",
				"SubSection": "Prepare",
				"LevelOfRisk": "High",
				"AssessmentMethod": "Automated",
				"Description": "Create plans to help you respond to, communicate during, and recover from an incident. For example, you can start an incident response plan with the most likely scenarios for your workload and organization. Include how you would communicate and escalate both internally and externally.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_develop_management_plans.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC10-BP03",
			"Description": "It's important for your incident responders to understand when and how the forensic investigation fits into your response plan. Your organization should define what evidence is collected and what tools are used in the process. Identify and prepare forensic investigation capabilities that are suitable, including external specialists, tools, and automation. A key decision that you should make upfront is if you will collect data from a live system. Some data, such as the contents of volatile memory or active network connections, will be lost if the system is powered off or rebooted.Your response team can combine tools, such as AWS Systems Manager, Amazon EventBridge, and AWS Lambda, to automatically run forensic tools within an operating system and VPC traffic mirroring to obtain a network packet capture, to gather non-persistent evidence. Conduct other activities, such as log analysis or analyzing disk images, in a dedicated security account with customized forensic workstations and tools accessible to your responders.Routinely ship relevant logs to a data store that provides high durability and integrity. Responders should have access to those logs. AWS offers several tools that can make log investigation easier, such as Amazon Athena, Amazon OpenSearch Service (OpenSearch Service), and Amazon CloudWatch Logs Insights. Additionally, preserve evidence securely using Amazon Simple Storage Service (Amazon S3) Object Lock. This service follows the WORM (write-once- read-many) model and prevents objects from being deleted or overwritten for a defined period. As forensic investigation techniques require specialist training, you might need to engage external specialists.",
			"Attributes": [
			  {
				"Name": "SEC10-BP03 Prepare forensic capabilities",
				"WellArchitectedQuestionId": "incident-response",
				"WellArchitectedPracticeId": "sec_incident_response_prepare_forensic",
				"Section": "Incident response",
				"SubSection": "Prepare",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "It's important for your incident responders to understand when and how the forensic investigation fits into your response plan. Your organization should define what evidence is collected and what tools are used in the process. Identify and prepare forensic investigation capabilities that are suitable, including external specialists, tools, and automation. A key decision that you should make upfront is if you will collect data from a live system. Some data, such as the contents of volatile memory or active network connections, will be lost if the system is powered off or rebooted.Your response team can combine tools, such as AWS Systems Manager, Amazon EventBridge, and AWS Lambda, to automatically run forensic tools within an operating system and VPC traffic mirroring to obtain a network packet capture, to gather non-persistent evidence. Conduct other activities, such as log analysis or analyzing disk images, in a dedicated security account with customized forensic workstations and tools accessible to your responders.Routinely ship relevant logs to a data store that provides high durability and integrity. Responders should have access to those logs. AWS offers several tools that can make log investigation easier, such as Amazon Athena, Amazon OpenSearch Service (OpenSearch Service), and Amazon CloudWatch Logs Insights. Additionally, preserve evidence securely using Amazon Simple Storage Service (Amazon S3) Object Lock. This service follows the WORM (write-once- read-many) model and prevents objects from being deleted or overwritten for a defined period. As forensic investigation techniques require specialist training, you might need to engage external specialists.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_prepare_forensic.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC10-BP05",
			"Description": "Verify that incident responders have the correct access pre-provisioned in AWS to reduce the time needed for investigation through to recovery.Common anti-patterns:Using the root account for incident response.Altering existing accounts.Manipulating IAM permissions directly when providing just-in-time privilege elevation.",
			"Attributes": [
			  {
				"Name": "SEC10-BP05 Pre-provision access",
				"WellArchitectedQuestionId": "incident-response",
				"WellArchitectedPracticeId": "sec_incident_response_pre_provision_access",
				"Section": "Incident response",
				"SubSection": "Prepare",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Verify that incident responders have the correct access pre-provisioned in AWS to reduce the time needed for investigation through to recovery.Common anti-patterns:Using the root account for incident response.Altering existing accounts.Manipulating IAM permissions directly when providing just-in-time privilege elevation.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_provision_access.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC10-BP06",
			"Description": "Ensure that security personnel have the right tools pre-deployed into AWS to reduce the time for investigation through to recovery.To automate security engineering and operations functions, you can use a comprehensive set of APIs and tools from AWS. You can fully automate identity management, network security, data protection, and monitoring capabilities and deliver them using popular software development methods that you already have in place. When you build security automation, your system can monitor, review, and initiate a response, rather than having people monitor your security position and manually react to events. An effective way to automatically provide searchable and relevant log data across AWS services to your incident responders is to enable Amazon Detective.If your incident response teams continue to respond to alerts in the same way, they risk alert fatigue. Over time, the team can become desensitized to alerts and can either make mistakes handling ordinary situations or miss unusual alerts. Automation helps avoid alert fatigue by using functions that process the repetitive and ordinary alerts, leaving humans to handle the sensitive and unique incidents. Integrating anomaly detection systems, such as Amazon GuardDuty, AWS CloudTrail Insights, and Amazon CloudWatch Anomaly Detection, can reduce the burden of common threshold-based alerts.You can improve manual processes by programmatically automating steps in the process. After you define the remediation pattern to an event, you can decompose that pattern into actionable logic, and write the code to perform that logic. Responders can then execute that code to remediate the issue. Over time, you can automate more and more steps, and ultimately automatically handle whole classes of common incidents.For tools that execute within the operating system of your Amazon Elastic Compute Cloud (Amazon EC2) instance, you should evaluate using the AWS Systems Manager Run Command, which enables you to remotely and securely administrate instances using an agent that you install on your Amazon EC2 instance operating system. It requires the Systems Manager Agent (SSM Agent), which is installed by default on many Amazon Machine Images (AMIs). Be aware, though, that once an instance has been compromised, no responses from tools or agents running on it should be considered trustworthy.",
			"Attributes": [
			  {
				"Name": "SEC10-BP06 Pre-deploy tools",
				"WellArchitectedQuestionId": "incident-response",
				"WellArchitectedPracticeId": "sec_incident_response_pre_deploy_tools",
				"Section": "Incident response",
				"SubSection": "Prepare",
				"LevelOfRisk": "Low",
				"AssessmentMethod": "Automated",
				"Description": "Ensure that security personnel have the right tools pre-deployed into AWS to reduce the time for investigation through to recovery.To automate security engineering and operations functions, you can use a comprehensive set of APIs and tools from AWS. You can fully automate identity management, network security, data protection, and monitoring capabilities and deliver them using popular software development methods that you already have in place. When you build security automation, your system can monitor, review, and initiate a response, rather than having people monitor your security position and manually react to events. An effective way to automatically provide searchable and relevant log data across AWS services to your incident responders is to enable Amazon Detective.If your incident response teams continue to respond to alerts in the same way, they risk alert fatigue. Over time, the team can become desensitized to alerts and can either make mistakes handling ordinary situations or miss unusual alerts. Automation helps avoid alert fatigue by using functions that process the repetitive and ordinary alerts, leaving humans to handle the sensitive and unique incidents. Integrating anomaly detection systems, such as Amazon GuardDuty, AWS CloudTrail Insights, and Amazon CloudWatch Anomaly Detection, can reduce the burden of common threshold-based alerts.You can improve manual processes by programmatically automating steps in the process. After you define the remediation pattern to an event, you can decompose that pattern into actionable logic, and write the code to perform that logic. Responders can then execute that code to remediate the issue. Over time, you can automate more and more steps, and ultimately automatically handle whole classes of common incidents.For tools that execute within the operating system of your Amazon Elastic Compute Cloud (Amazon EC2) instance, you should evaluate using the AWS Systems Manager Run Command, which enables you to remotely and securely administrate instances using an agent that you install on your Amazon EC2 instance operating system. It requires the Systems Manager Agent (SSM Agent), which is installed by default on many Amazon Machine Images (AMIs). Be aware, though, that once an instance has been compromised, no responses from tools or agents running on it should be considered trustworthy.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_deploy_tools.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC10-BP07",
			"Description": "Game days, also known as simulations or exercises, are internal events that provide a structured opportunity to practice your incident management plans and procedures during a realistic scenario. These events should exercise responders using the same tools and techniques that would be used in a real-world scenario - even mimicking real-world environments. Game days are fundamentally about being prepared and iteratively improving your response capabilities. Some of the reasons you might find value in performing game day activities include:Validating readinessDeveloping confidence – learning from simulations and training staffFollowing compliance or contractual obligationsGenerating artifacts for accreditationBeing agile – incremental improvementBecoming faster and improving toolsRefining communication and escalationDeveloping comfort with the rare and the unexpectedFor these reasons, the value derived from participating in a simulation activity increases an organization's effectiveness during stressful events. Developing a simulation activity that is both realistic and beneficial can be a difficult exercise. Although testing your procedures or automation that handles well-understood events has certain advantages, it is just as valuable to participate in creative Security Incident Response Simulations (SIRS) activities to test yourself against the unexpected and continuously improve.Create custom simulations tailored to your environment, team, and tools. Find an issue and design your simulation around it. This could be something like a leaked credential, a server communicating with unwanted systems, or a misconfiguration that results in unauthorized exposure. Identify engineers who are familiar with your organization to create the scenario and another group to participate. The scenario should be realistic and challenging enough to be valuable. It should include the opportunity to get hands on with logging, notifications, escalations, and executing runbooks or automation. During the simulation, your responders should exercise their technical and organizational skills, and leaders should be involved to build their incident management skills. At the end of the simulation, celebrate the efforts of the team and look for ways to iterate, repeat, and expand into further simulations.AWS has created Incident Response Runbook templates that you can use not only to prepare your response efforts, but also as a basis for a simulation. When planning, a simulation can be broken into five phases.Evidence gathering: In this phase, a team will get alerts through various means, such as an internal ticketing system, alerts from monitoring tooling, anonymous tips, or even public news. Teams then start to review infrastructure and application logs to determine the source of the compromise. This step should also involve internal escalations and incident leadership. Once identified, teams move on to containing the incidentContain the incident: Teams will have determined there has been an incident and established the source of the compromise. Teams now should take action to contain it, for example, by disabling compromised credentials, isolating a compute resource, or revoking a role's permission.Eradicate the incident: Now that they've contained the incident, teams will work towards mitigating any vulnerabilities in applications or infrastructure configurations that were susceptible to the compromise. This could include rotating all credentials used for a workload, modifying Access Control Lists (ACLs) or changing network configurations.",
			"Attributes": [
			  {
				"Name": "SEC10-BP07 Run game days",
				"WellArchitectedQuestionId": "incident-response",
				"WellArchitectedPracticeId": "sec_incident_response_run_game_days",
				"Section": "Incident response",
				"SubSection": "Simulate",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Game days, also known as simulations or exercises, are internal events that provide a structured opportunity to practice your incident management plans and procedures during a realistic scenario. These events should exercise responders using the same tools and techniques that would be used in a real-world scenario - even mimicking real-world environments. Game days are fundamentally about being prepared and iteratively improving your response capabilities. Some of the reasons you might find value in performing game day activities include:Validating readinessDeveloping confidence – learning from simulations and training staffFollowing compliance or contractual obligationsGenerating artifacts for accreditationBeing agile – incremental improvementBecoming faster and improving toolsRefining communication and escalationDeveloping comfort with the rare and the unexpectedFor these reasons, the value derived from participating in a simulation activity increases an organization's effectiveness during stressful events. Developing a simulation activity that is both realistic and beneficial can be a difficult exercise. Although testing your procedures or automation that handles well-understood events has certain advantages, it is just as valuable to participate in creative Security Incident Response Simulations (SIRS) activities to test yourself against the unexpected and continuously improve.Create custom simulations tailored to your environment, team, and tools. Find an issue and design your simulation around it. This could be something like a leaked credential, a server communicating with unwanted systems, or a misconfiguration that results in unauthorized exposure. Identify engineers who are familiar with your organization to create the scenario and another group to participate. The scenario should be realistic and challenging enough to be valuable. It should include the opportunity to get hands on with logging, notifications, escalations, and executing runbooks or automation. During the simulation, your responders should exercise their technical and organizational skills, and leaders should be involved to build their incident management skills. At the end of the simulation, celebrate the efforts of the team and look for ways to iterate, repeat, and expand into further simulations.AWS has created Incident Response Runbook templates that you can use not only to prepare your response efforts, but also as a basis for a simulation. When planning, a simulation can be broken into five phases.Evidence gathering: In this phase, a team will get alerts through various means, such as an internal ticketing system, alerts from monitoring tooling, anonymous tips, or even public news. Teams then start to review infrastructure and application logs to determine the source of the compromise. This step should also involve internal escalations and incident leadership. Once identified, teams move on to containing the incidentContain the incident: Teams will have determined there has been an incident and established the source of the compromise. Teams now should take action to contain it, for example, by disabling compromised credentials, isolating a compute resource, or revoking a role's permission.Eradicate the incident: Now that they've contained the incident, teams will work towards mitigating any vulnerabilities in applications or infrastructure configurations that were susceptible to the compromise. This could include rotating all credentials used for a workload, modifying Access Control Lists (ACLs) or changing network configurations.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_run_game_days.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC10-BP04",
			"Description": "Automate containment and recovery of an incident to reduce response times and organizational impact.Once you create and practice the processes and tools from your playbooks, you can deconstruct the logic into a code-based solution, which can be used as a tool by many responders to automate the response and remove variance or guess-work by your responders. This can speed up the lifecycle of a response. The next goal is to enable this code to be fully automated by being invoked by the alerts or events themselves, rather than by a human responder, to create an event-driven response. These processes should also automatically add relevant data to your security systems. For example, an incident involving traffic from an unwanted IP address can automatically populate an AWS WAF block list or Network Firewall rule group to prevent further activity.With an event-driven response system, a detective mechanism triggers a responsive mechanism to automatically remediate the event. You can use event-driven response capabilities to reduce the time-to-value between detective mechanisms and responsive mechanisms. To create this event-driven architecture, you can use AWS Lambda, which is a serverless compute service that runs your code in response to events and automatically manages the underlying compute resources for you. For example, assume that you have an AWS account with the AWS CloudTrail service enabled. If CloudTrail is ever disabled (through the cloudtrail:StopLogging API call), you can use Amazon EventBridge to monitor for the specific cloudtrail:StopLogging event, and invoke a Lambda function to call cloudtrail:StartLogging to restart logging.",
			"Attributes": [
			  {
				"Name": "SEC10-BP04 Automate containment capability",
				"WellArchitectedQuestionId": "incident-response",
				"WellArchitectedPracticeId": "sec_incident_response_auto_contain",
				"Section": "Incident response",
				"SubSection": "Iterate",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Automate containment and recovery of an incident to reduce response times and organizational impact.Once you create and practice the processes and tools from your playbooks, you can deconstruct the logic into a code-based solution, which can be used as a tool by many responders to automate the response and remove variance or guess-work by your responders. This can speed up the lifecycle of a response. The next goal is to enable this code to be fully automated by being invoked by the alerts or events themselves, rather than by a human responder, to create an event-driven response. These processes should also automatically add relevant data to your security systems. For example, an incident involving traffic from an unwanted IP address can automatically populate an AWS WAF block list or Network Firewall rule group to prevent further activity.With an event-driven response system, a detective mechanism triggers a responsive mechanism to automatically remediate the event. You can use event-driven response capabilities to reduce the time-to-value between detective mechanisms and responsive mechanisms. To create this event-driven architecture, you can use AWS Lambda, which is a serverless compute service that runs your code in response to events and automatically manages the underlying compute resources for you. For example, assume that you have an AWS account with the AWS CloudTrail service enabled. If CloudTrail is ever disabled (through the cloudtrail:StopLogging API call), you can use Amazon EventBridge to monitor for the specific cloudtrail:StopLogging event, and invoke a Lambda function to call cloudtrail:StartLogging to restart logging.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_auto_contain.html#implementation-guidance."
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "SEC11-BP02",
			"Description": "Automate the testing for security properties throughout the development and release lifecycle. Automation makes it easier to consistently and repeatably identify potential issues in software prior to release, which reduces the risk of security issues in the software being provided. The goal of automated testing is to provide a programmatic way of detecting potential issues early and often throughout the development lifecycle. When you automate regression testing, you can rerun functional and non-functional tests to verify that previously tested software still performs as expected after a change. When you define security unit tests to check for common misconfigurations, such as broken or missing authentication, you can identify and fix these issues early in the development process. Test automation uses purpose-built test cases for application validation, based on the application’s requirements and desired functionality. The result of the automated testing is based on comparing the generated test output to its respective expected output, which expedites the overall testing lifecycle. Testing methodologies such as regression testing and unit test suites are best suited for automation. Automating the testing of security properties allows builders to receive automated feedback without having to wait for a security review. Automated tests in the form of static or dynamic code analysis can increase code quality and help detect potential software issues early in the development lifecycle.",
			"Attributes": [
			  {
				"Name": "SEC11-BP02 Automate testing throughout the development and release lifecycle",
				"WellArchitectedQuestionId": "application-security",
				"WellArchitectedPracticeId": "sec_appsec_automate_testing_throughout_lifecycle",
				"Section": "Application Security",
				"LevelOfRisk": "Medium",
				"AssessmentMethod": "Automated",
				"Description": "Automate the testing for security properties throughout the development and release lifecycle. Automation makes it easier to consistently and repeatably identify potential issues in software prior to release, which reduces the risk of security issues in the software being provided. The goal of automated testing is to provide a programmatic way of detecting potential issues early and often throughout the development lifecycle. When you automate regression testing, you can rerun functional and non-functional tests to verify that previously tested software still performs as expected after a change. When you define security unit tests to check for common misconfigurations, such as broken or missing authentication, you can identify and fix these issues early in the development process. Test automation uses purpose-built test cases for application validation, based on the application’s requirements and desired functionality. The result of the automated testing is based on comparing the generated test output to its respective expected output, which expedites the overall testing lifecycle. Testing methodologies such as regression testing and unit test suites are best suited for automation. Automating the testing of security properties allows builders to receive automated feedback without having to wait for a security review. Automated tests in the form of static or dynamic code analysis can increase code quality and help detect potential software issues early in the development lifecycle.",
				"ImplementationGuidanceUrl": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_appsec_automate_testing_throughout_lifecycle.html#implementation-guidance."
			  }
			],
			"Checks": [
			  "ecr_repositories_scan_images_on_push_enabled",
			  "ecr_repositories_scan_vulnerabilities_in_latest_image"
			]
		  }
		]
	  }
	  `
	var comp CFramework
	err := json.Unmarshal([]byte(jsonData), &comp)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Create a new Go file and write the contents
	file, err := os.Create("requirements.go")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	// Write package declaration
	file.WriteString("package main\n\n")

	// Write struct definitions
	file.WriteString("type NistComp struct {\n")
	file.WriteString("\tProvider string\n")
	file.WriteString("\tFramework string\n")
	file.WriteString("\tFrameworkdesc string\n")
	file.WriteString("\tId string\n")
	file.WriteString("\tDescription string\n")
	file.WriteString("\tName string\n")
	file.WriteString("\tWellArchitectedQuestionId string\n")
	file.WriteString("\tWellArchitectedPracticeId string\n")
	file.WriteString("\tSection string\n")
	file.WriteString("\tSubSection string\n")
	file.WriteString("\tLevelOfRisk string\n")
	file.WriteString("\tAssessmentMethod string\n")
	file.WriteString("\tImplementationGuidanceUrl string\n")
	file.WriteString("\tChecks []string\n")
	file.WriteString("}\n\n")

	// Write requirements list
	// file.WriteString("var Requirements = []Requirement{\n")
	var provider = "AWS"
	var framework = "SOC2"
	var Frameworkdesc = "System and Organization Controls (SOC), defined by the American Institute of Certified Public Accountants (AICPA), is the name of a set of reports that's produced during an audit. It's intended for use by service organizations (organizations that provide information systems as a service to other organizations) to issue validated reports of internal controls over those information systems to the users of those services. The reports focus on controls grouped into five categories known as Trust Service Principles."
	var i int64
	for _, req := range comp.Requirements {
		i++
		// file.WriteString(fmt.Sprintf("\tvar soc2_%s = &NistComp{\n", req.Id))
		replacer := strings.NewReplacer(" ", "_", "-", "_", ",", "_")
		file.WriteString(fmt.Sprintf("\tvar frame_secu_%s = &NistComp{\n", replacer.Replace(req.Id)))
		file.WriteString(fmt.Sprintf("\t\tFramework: \"%s\",\n", framework))
		file.WriteString(fmt.Sprintf("\t\tProvider: \"%s\",\n", provider))
		file.WriteString(fmt.Sprintf("\t\tFrameworkdesc: \"%s\",\n", Frameworkdesc))
		file.WriteString(fmt.Sprintf("\t\tId: \"%s\",\n", req.Id))
		file.WriteString(fmt.Sprintf("\t\tDescription: \"%s\",\n", req.Description))
		// file.WriteString(fmt.Sprintf("\t\tAttributes: []struct {\n"))
		for _, attr := range req.Attributes {
			if attr.Name != "" {
				file.WriteString(fmt.Sprintf("\t\tName: \"%s\",\n", attr.Name))
			}
			if attr.WellArchitectedQuestionId != "" {
				file.WriteString(fmt.Sprintf("\t\tWellArchitectedQuestionId: \"%s\",\n", attr.WellArchitectedQuestionId))
			}
			if attr.WellArchitectedPracticeId != "" {
				file.WriteString(fmt.Sprintf("\t\tWellArchitectedPracticeId: \"%s\",\n", attr.WellArchitectedPracticeId))
			}
			if attr.Section != "" {
				file.WriteString(fmt.Sprintf("\t\tSection: \"%s\",\n", attr.Section))
			}
			if attr.SubSection != "" {
				file.WriteString(fmt.Sprintf("\t\tSubSection: \"%s\",\n", attr.SubSection))
			}
			if attr.LevelOfRisk != "" {
				file.WriteString(fmt.Sprintf("\t\tLevelOfRisk: \"%s\",\n", attr.LevelOfRisk))
			}
			if attr.AssessmentMethod != "" {
				file.WriteString(fmt.Sprintf("\t\tAssessmentMethod: \"%s\",\n", attr.AssessmentMethod))
			}

			if attr.ImplementationGuidanceUrl != "" {
				file.WriteString(fmt.Sprintf("\t\tImplementationGuidanceUrl: \"%s\",\n", attr.ImplementationGuidanceUrl))
			}
		}
		// file.WriteString(fmt.Sprintf("\t\t},\n"))
		file.WriteString(fmt.Sprintf("\t\tChecks: %#v,\n", req.Checks))
		file.WriteString(fmt.Sprintf("\t}\n"))

	}
	fmt.Println(i)

}
