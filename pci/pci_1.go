package main

type NistComp struct {
	Provider      string
	Framework     string
	Frameworkdesc string
	Id            string
	Name          string
	Description   string
	ItemId        string
	Section       string
	SubSection    string
	Service       string
	Type          string
	Checks        []string
}

var Pci_autoscaling = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "autoscaling",
	Name:          "Auto Scaling",
	Description:   "This control checks whether your Auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks. PCI DSS does not require load balancing or highly available configurations. However, this check aligns with AWS best practices.",
	ItemId:        "autoscaling",
	Service:       "autoscaling",
	Checks:        []string{},
}
var Pci_cloudtrail = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "cloudtrail",
	Name:          "CloudTrail",
	Description:   "This section contains recommendations for configuring CloudTrail resources and options.",
	ItemId:        "cloudtrail",
	Service:       "cloudtrail",
	Checks:        []string{"cloudtrail_kms_encryption_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_log_file_validation_enabled", "cloudtrail_cloudwatch_logging_enabled"},
}
var Pci_codebuild = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "codebuild",
	Name:          "CodeBuild",
	Description:   "This section contains recommendations for configuring CodeBuild resources and options.",
	ItemId:        "codebuild",
	Service:       "codebuild",
	Checks:        []string{},
}
var Pci_config = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "config",
	Name:          "Config",
	Description:   "This section contains recommendations for configuring AWS Config.",
	ItemId:        "config",
	Service:       "config",
	Checks:        []string{"config_recorder_all_regions_enabled"},
}
var Pci_cw = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "cw",
	Name:          "CloudWatch",
	Description:   "This section contains recommendations for configuring CloudWatch resources and options.",
	ItemId:        "cw",
	Service:       "cloudwatch",
	Checks:        []string{"cloudwatch_log_metric_filter_root_usage"},
}
var Pci_dms = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "dms",
	Name:          "DMS",
	Description:   "This section contains recommendations for configuring AWS DMS resources and options.",
	ItemId:        "dms",
	Service:       "dms",
	Checks:        []string{},
}
var Pci_ec2 = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "ec2",
	Name:          "EC2",
	Description:   "This section contains recommendations for configuring EC2 resources and options.",
	ItemId:        "ec2",
	Service:       "ec2",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_securitygroup_default_restrict_traffic", "ec2_elastic_ip_unassigned", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389", "vpc_flow_logs_enabled"},
}
var Pci_elbv2 = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "elbv2",
	Name:          "ELBV2",
	Description:   "This section contains recommendations for configuring Elastic Load Balancer resources and options.",
	ItemId:        "elbv2",
	Service:       "elbv2",
	Checks:        []string{},
}
var Pci_elasticsearch = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "elasticsearch",
	Name:          "Elasticsearch",
	Description:   "This section contains recommendations for configuring Elasticsearch resources and options.",
	ItemId:        "elasticsearch",
	Service:       "elasticsearch",
	Checks:        []string{"opensearch_service_domains_encryption_at_rest_enabled"},
}
var Pci_guardduty = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "guardduty",
	Name:          "GuardDuty",
	Description:   "This section contains recommendations for configuring AWS GuardDuty resources and options.",
	ItemId:        "guardduty",
	Service:       "guardduty",
	Checks:        []string{"guardduty_is_enabled"},
}
var Pci_iam = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "iam",
	Name:          "IAM",
	Description:   "This section contains recommendations for configuring AWS IAM resources and options.",
	ItemId:        "iam",
	Service:       "iam",
	Checks:        []string{"iam_no_root_access_key", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "iam_user_accesskey_unused", "iam_user_console_access_unused", "iam_password_policy_minimum_length_14", "iam_password_policy_lowercase", "iam_password_policy_number", "iam_password_policy_number", "iam_password_policy_symbol", "iam_password_policy_uppercase"},
}
var Pci_kms = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "kms",
	Name:          "KMS",
	Description:   "This section contains recommendations for configuring AWS KMS resources and options.",
	ItemId:        "kms",
	Service:       "kms",
	Checks:        []string{"kms_cmk_rotation_enabled"},
}
var Pci_lambda = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "lambda",
	Name:          "Lambda",
	Description:   "This section contains recommendations for configuring Lambda resources and options.",
	ItemId:        "lambda",
	Service:       "lambda",
	Checks:        []string{"awslambda_function_url_public", "awslambda_function_not_publicly_accessible"},
}
var Pci_opensearch = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "opensearch",
	Name:          "OpenSearch",
	Description:   "This section contains recommendations for configuring OpenSearch resources and options.",
	ItemId:        "opensearch",
	Service:       "opensearch",
	Checks:        []string{"opensearch_service_domains_encryption_at_rest_enabled"},
}
var Pci_rds = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "rds",
	Name:          "RDS",
	Description:   "This section contains recommendations for configuring AWS RDS resources and options.",
	ItemId:        "rds",
	Service:       "rds",
	Checks:        []string{"rds_snapshots_public_access", "rds_instance_no_public_access"},
}
var Pci_redshift = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "redshift",
	Name:          "Redshift",
	Description:   "This section contains recommendations for configuring AWS Redshift resources and options.",
	ItemId:        "redshift",
	Service:       "redshift",
	Checks:        []string{"redshift_cluster_public_access"},
}
var Pci_s3 = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "s3",
	Name:          "S3",
	Description:   "This section contains recommendations for configuring AWS S3 resources and options.",
	ItemId:        "s3",
	Service:       "s3",
	Checks:        []string{"s3_bucket_policy_public_write_access", "s3_bucket_public_access", "s3_bucket_default_encryption", "s3_bucket_secure_transport_policy", "s3_bucket_public_access"},
}
var Pci_sagemaker = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "sagemaker",
	Name:          "SageMaker",
	Description:   "This section contains recommendations for configuring AWS Sagemaker resources and options.",
	ItemId:        "sagemaker",
	Service:       "sagemaker",
	Checks:        []string{"sagemaker_notebook_instance_without_direct_internet_access_configured"},
}
var Pci_ssm = &NistComp{
	Framework:     "PCI",
	Provider:      "AWS",
	Frameworkdesc: "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard. It's administered by the PCI Security Standards Council, which was founded by American Express, Discover Financial Services, JCB International, MasterCard Worldwide, and Visa Inc. PCI DSS applies to entities that store, process, or transmit cardholder data (CHD) or sensitive authentication data (SAD). This includes, but isn't limited to, merchants, processors, acquirers, issuers, and service providers. The PCI DSS is mandated by the card brands and administered by the Payment Card Industry Security Standards Council.",
	Id:            "ssm",
	Name:          "SSM",
	Description:   "This section contains recommendations for configuring AWS SSM resources and options.",
	ItemId:        "ssm",
	Service:       "ssm",
	Checks:        []string{"ssm_managed_compliant_patching", "ssm_managed_compliant_patching", "ec2_instance_managed_by_ssm"},
}
