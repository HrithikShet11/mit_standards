package main

type NistComp struct {
	Provider string
	Framework string
	Frameworkdesc string
	Id string
	Name string
	Description string
	Section string
	Service string
	Checks []string
}

	var foundational_sec_account = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "account",
		Name: "Account",
		Description: "This section contains recommendations for configuring AWS Account.",
		Section: "Account",
		Service: "account",
		Checks: []string{"account_security_contact_information_is_registered"},
	}
	var foundational_sec_acm = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "acm",
		Name: "ACM",
		Description: "This section contains recommendations for configuring ACM resources.",
		Section: "Acm",
		Service: "acm",
		Checks: []string{"account_security_contact_information_is_registered"},
	}
	var foundational_sec_api_gateway = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "api-gateway",
		Name: "API Gateway",
		Description: "This section contains recommendations for configuring API Gateway resources.",
		Section: "API Gateway",
		Service: "apigateway",
		Checks: []string{"apigateway_restapi_logging_enabled", "apigateway_restapi_client_certificate_enabled", "apigateway_restapi_waf_acl_attached", "apigatewayv2_api_authorizers_enabled", "apigatewayv2_api_access_logging_enabled"},
	}
	var foundational_sec_auto_scaling = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "auto-scaling",
		Name: "Benchmark: Auto Scaling",
		Description: "This section contains recommendations for configuring Auto Scaling resources and options.",
		Section: "Auto Scaling",
		Service: "autoscaling",
		Checks: []string{},
	}
	var foundational_sec_cloudformation = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "cloudformation",
		Name: "Benchmark: CloudFormation",
		Description: "This section contains recommendations for configuring CloudFormation resources and options.",
		Section: "CloudFormation",
		Service: "cloudformation",
		Checks: []string{},
	}
	var foundational_sec_cloudfront = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "cloudfront",
		Name: "Benchmark: CloudFront",
		Description: "This section contains recommendations for configuring CloudFront resources and options.",
		Section: "CloudFront",
		Service: "cloudfront",
		Checks: []string{"cloudfront_distributions_https_enabled", "cloudfront_distributions_logging_enabled", "cloudfront_distributions_using_waf", "cloudfront_distributions_field_level_encryption_enabled", "cloudfront_distributions_using_deprecated_ssl_protocols"},
	}
	var foundational_sec_cloudtrail = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "cloudtrail",
		Name: "Benchmark: CloudTrail",
		Description: "This section contains recommendations for configuring CloudTrail resources and options.",
		Section: "CloudTrail",
		Service: "cloudtrail",
		Checks: []string{"cloudtrail_multi_region_enabled", "cloudtrail_kms_encryption_enabled", "cloudtrail_log_file_validation_enabled", "cloudtrail_cloudwatch_logging_enabled"},
	}
	var foundational_sec_codebuild = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "codebuild",
		Name: "Benchmark: CodeBuild",
		Description: "This section contains recommendations for configuring CodeBuild resources and options.",
		Section: "CodeBuild",
		Service: "codebuild",
		Checks: []string{},
	}
	var foundational_sec_config = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "config",
		Name: "Benchmark: Config",
		Description: "This section contains recommendations for configuring AWS Config.",
		Section: "Config",
		Service: "config",
		Checks: []string{"config_recorder_all_regions_enabled"},
	}
	var foundational_sec_dms = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "dms",
		Name: "Benchmark: DMS",
		Description: "This section contains recommendations for configuring AWS DMS resources and options.",
		Section: "DMS",
		Service: "dms",
		Checks: []string{},
	}
	var foundational_sec_dynamodb = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "dynamodb",
		Name: "Benchmark: DynamoDB",
		Description: "This section contains recommendations for configuring AWS Dynamo DB resources and options.",
		Section: "DynamoDB",
		Service: "dynamodb",
		Checks: []string{"dynamodb_tables_pitr_enabled", "dynamodb_accelerator_cluster_encryption_enabled"},
	}
	var foundational_sec_ec2 = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "ec2",
		Name: "Benchmark: EC2",
		Description: "This section contains recommendations for configuring EC2 resources and options.",
		Section: "EC2",
		Service: "ec2",
		Checks: []string{"ec2_ebs_public_snapshot", "ec2_securitygroup_default_restrict_traffic", "ec2_ebs_volume_encryption", "ec2_instance_older_than_specific_days", "vpc_flow_logs_enabled", "ec2_ebs_default_encryption", "ec2_instance_imdsv2_enabled", "ec2_instance_public_ip", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_not_used"},
	}
	var foundational_sec_ecr = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "ecr",
		Name: "Benchmark: Elastic Container Registry",
		Description: "This section contains recommendations for configuring AWS ECR resources and options.",
		Section: "ECR",
		Service: "ecr",
		Checks: []string{"ecr_repositories_scan_images_on_push_enabled", "ecr_repositories_lifecycle_policy_enabled"},
	}
	var foundational_sec_ecs = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "ecs",
		Name: "Benchmark: Elastic Container Service",
		Description: "This section contains recommendations for configuring ECS resources and options.",
		Section: "ECS",
		Service: "ecs",
		Checks: []string{"ecs_task_definitions_no_environment_secrets"},
	}
	var foundational_sec_efs = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "efs",
		Name: "Benchmark: EFS",
		Description: "This section contains recommendations for configuring AWS EFS resources and options.",
		Section: "EFS",
		Service: "efs",
		Checks: []string{"efs_encryption_at_rest_enabled", "efs_have_backup_enabled"},
	}
	var foundational_sec_eks = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "eks",
		Name: "Benchmark: EKS",
		Description: "This section contains recommendations for configuring AWS EKS resources and options.",
		Section: "EKS",
		Service: "eks",
		Checks: []string{},
	}
	var foundational_sec_elastic_beanstalk = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "elastic-beanstalk",
		Name: "Benchmark: Elastic Beanstalk",
		Description: "This section contains recommendations for configuring AWS Elastic Beanstalk resources and options.",
		Section: "Elastic Beanstalk",
		Service: "elasticbeanstalk",
		Checks: []string{},
	}
	var foundational_sec_elb = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "elb",
		Name: "Benchmark: ELB",
		Description: "This section contains recommendations for configuring Elastic Load Balancer resources and options.",
		Section: "ELB",
		Service: "elb",
		Checks: []string{"elbv2_logging_enabled", "elb_logging_enabled", "elbv2_deletion_protection", "elbv2_desync_mitigation_mode"},
	}
	var foundational_sec_elbv2 = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "elbv2",
		Name: "Benchmark: ELBv2",
		Description: "This section contains recommendations for configuring Elastic Load Balancer resources and options.",
		Section: "ELBv2",
		Service: "elbv2",
		Checks: []string{},
	}
	var foundational_sec_emr = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "emr",
		Name: "Benchmark: EMR",
		Description: "This section contains recommendations for configuring EMR resources.",
		Section: "EMR",
		Service: "emr",
		Checks: []string{"emr_cluster_master_nodes_no_public_ip"},
	}
	var foundational_sec_elasticsearch = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "elasticsearch",
		Name: "Benchmark: Elasticsearch",
		Description: "This section contains recommendations for configuring Elasticsearch resources and options.",
		Section: "ElasticSearch",
		Service: "elasticsearch",
		Checks: []string{"opensearch_service_domains_encryption_at_rest_enabled", "opensearch_service_domains_node_to_node_encryption_enabled", "opensearch_service_domains_audit_logging_enabled", "opensearch_service_domains_audit_logging_enabled", "opensearch_service_domains_https_communications_enforced"},
	}
	var foundational_sec_guardduty = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "guardduty",
		Name: "Benchmark: GuardDuty",
		Description: "This section contains recommendations for configuring AWS GuardDuty resources and options.",
		Section: "GuardDuty",
		Service: "guardduty",
		Checks: []string{"guardduty_is_enabled"},
	}
	var foundational_sec_iam = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "iam",
		Name: "Benchmark: IAM",
		Description: "This section contains recommendations for configuring AWS IAM resources and options.",
		Section: "IAM",
		Service: "iam",
		Checks: []string{"iam_rotate_access_key_90_days", "iam_no_root_access_key", "iam_user_mfa_enabled_console_access", "iam_root_hardware_mfa_enabled", "iam_password_policy_minimum_length_14", "iam_user_accesskey_unused", "iam_user_console_access_unused", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges"},
	}
	var foundational_sec_kinesis = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "kinesis",
		Name: "Benchmark: Kinesis",
		Description: "This section contains recommendations for configuring AWS Kinesis resources and options.",
		Section: "Kinesis",
		Service: "kinesis",
		Checks: []string{},
	}
	var foundational_sec_kms = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "kms",
		Name: "Benchmark: KMS",
		Description: "This section contains recommendations for configuring AWS KMS resources and options.",
		Section: "KMS",
		Service: "kms",
		Checks: []string{},
	}
	var foundational_sec_lambda = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "lambda",
		Name: "Benchmark: Lambda",
		Description: "This section contains recommendations for configuring Lambda resources and options.",
		Section: "Lambda",
		Service: "lambda",
		Checks: []string{"awslambda_function_url_public", "awslambda_function_using_supported_runtimes"},
	}
	var foundational_sec_network_firewall = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "network-firewall",
		Name: "Benchmark: Network Firewall",
		Description: "This section contains recommendations for configuring Network Firewall resources and options.",
		Section: "Network Firewall",
		Service: "network-firewall",
		Checks: []string{},
	}
	var foundational_sec_opensearch = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "opensearch",
		Name: "Benchmark: OpenSearch",
		Description: "This section contains recommendations for configuring OpenSearch resources and options.",
		Section: "OpenSearch",
		Service: "opensearch",
		Checks: []string{"opensearch_service_domains_not_publicly_accessible"},
	}
	var foundational_sec_rds = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "rds",
		Name: "Benchmark: RDS",
		Description: "This section contains recommendations for configuring AWS RDS resources and options.",
		Section: "RDS",
		Service: "rds",
		Checks: []string{"rds_snapshots_public_access", "rds_instance_no_public_access", "rds_instance_storage_encrypted", "rds_instance_storage_encrypted", "rds_instance_multi_az", "rds_instance_enhanced_monitoring_enabled", "rds_instance_deletion_protection", "rds_instance_integration_cloudwatch_logs", "rds_instance_minor_version_upgrade_enabled", "rds_instance_multi_az"},
	}
	var foundational_sec_redshift = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "redshift",
		Name: "Benchmark: Redshift",
		Description: "This section contains recommendations for configuring AWS Redshift resources and options.",
		Section: "Redshift",
		Service: "redshift",
		Checks: []string{"redshift_cluster_public_access", "redshift_cluster_automated_snapshot", "redshift_cluster_automated_snapshot", "redshift_cluster_automatic_upgrades"},
	}
	var foundational_sec_s3 = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "s3",
		Name: "Benchmark: S3",
		Description: "This section contains recommendations for configuring AWS S3 resources and options.",
		Section: "S3",
		Service: "s3",
		Checks: []string{"s3_account_level_public_access_blocks", "s3_account_level_public_access_blocks", "s3_bucket_policy_public_write_access", "s3_bucket_default_encryption", "s3_bucket_secure_transport_policy", "s3_bucket_public_access", "s3_bucket_server_access_logging_enabled", "s3_bucket_object_versioning", "s3_bucket_acl_prohibited"},
	}
	var foundational_sec_sagemaker = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "sagemaker",
		Name: "Benchmark: SageMaker",
		Description: "This section contains recommendations for configuring AWS Sagemaker resources and options.",
		Section: "SageMaker",
		Service: "sagemaker",
		Checks: []string{"sagemaker_notebook_instance_without_direct_internet_access_configured", "sagemaker_notebook_instance_vpc_settings_configured", "sagemaker_notebook_instance_root_access_disabled"},
	}
	var foundational_sec_secretsmanager = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "secretsmanager",
		Name: "Benchmark: Secrets Manager",
		Description: "This section contains recommendations for configuring AWS Secrets Manager resources.",
		Section: "Secrets Manager",
		Service: "secretsmanager",
		Checks: []string{"secretsmanager_automatic_rotation_enabled", "secretsmanager_automatic_rotation_enabled"},
	}
	var foundational_sec_sns = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "sns",
		Name: "Benchmark: SNS",
		Description: "This section contains recommendations for configuring AWS SNS resources and options.",
		Section: "SNS",
		Service: "sns",
		Checks: []string{"sns_topics_kms_encryption_at_rest_enabled"},
	}
	var foundational_sec_sqs = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "sqs",
		Name: "Benchmark: SQS",
		Description: "This section contains recommendations for configuring AWS SQS resources and options.",
		Section: "SQS",
		Service: "sqs",
		Checks: []string{"sqs_queues_server_side_encryption_enabled"},
	}
	var foundational_sec_ssm = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "ssm",
		Name: "Benchmark: SSM",
		Description: "This section contains recommendations for configuring AWS Systems Manager resources and options.",
		Section: "SSM",
		Service: "ssm",
		Checks: []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching", "ssm_managed_compliant_patching"},
	}
	var foundational_sec_waf = &NistComp{
		Framework: "AWS-Foundational-Security-Best-Practices",
		Provider: "AWS",
		Frameworkdesc: "The AWS Foundational Security Best Practices standard is a set of controls that detect when your deployed accounts and resources deviate from security best practices.",
		Id: "waf",
		Name: "Benchmark: WAF",
		Description: "This section contains recommendations for configuring AWS WAF resources and options.",
		Section: "WAF",
		Service: "waf",
		Checks: []string{},
	}
