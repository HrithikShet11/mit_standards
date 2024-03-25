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

var cisa_your_systems_1 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-systems-1",
	Name:          "Your Systems-1",
	Description:   "Learn what is on your network. Maintain inventories of hardware and software assets to know what is in play and at-risk from attack.",
	Section:       "your systems",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ec2_instance_older_than_specific_days", "ssm_managed_compliant_patching", "ec2_elastic_ip_unassigned"},
}
var cisa_your_systems_2 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-systems-2",
	Name:          "Your Systems-2",
	Description:   "Leverage automatic updates for all operating systems and third-party software.",
	Section:       "your systems",
	Checks:        []string{"rds_instance_minor_version_upgrade_enabled", "redshift_cluster_automatic_upgrades", "ssm_managed_compliant_patching"},
}
var cisa_your_systems_3 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-systems-3",
	Name:          "Your Systems-3",
	Description:   "Implement security configurations for all hardware and software assets.",
	Section:       "your systems",
	Checks:        []string{"apigateway_restapi_client_certificate_enabled", "apigateway_restapi_logging_enabled", "apigateway_restapi_waf_acl_attached", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_kms_encryption_enabled", "cloudtrail_log_file_validation_enabled", "codebuild_project_user_controlled_buildspec", "dynamodb_accelerator_cluster_encryption_enabled", "dynamodb_tables_kms_cmk_encryption_enabled", "dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "ec2_ebs_volume_encryption", "ec2_ebs_public_snapshot", "ec2_ebs_default_encryption", "ec2_instance_public_ip", "efs_encryption_at_rest_enabled", "efs_have_backup_enabled", "elb_logging_enabled", "elbv2_deletion_protection", "elbv2_waf_acl_attached", "elbv2_ssl_listeners", "elb_ssl_listeners", "emr_cluster_master_nodes_no_public_ip", "opensearch_service_domains_encryption_at_rest_enabled", "opensearch_service_domains_cloudwatch_logging_enabled", "opensearch_service_domains_node_to_node_encryption_enabled", "guardduty_is_enabled", "iam_password_policy_minimum_length_14", "iam_password_policy_lowercase", "iam_password_policy_number", "iam_password_policy_number", "iam_password_policy_symbol", "iam_password_policy_uppercase", "iam_no_custom_policy_permissive_role_assumption", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_no_root_access_key", "iam_rotate_access_key_90_days", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access", "iam_user_accesskey_unused", "iam_user_console_access_unused", "kms_cmk_rotation_enabled", "awslambda_function_not_publicly_accessible", "awslambda_function_not_publicly_accessible", "cloudwatch_log_group_kms_encryption_enabled", "cloudwatch_log_group_kms_encryption_enabled", "rds_instance_enhanced_monitoring_enabled", "rds_instance_backup_enabled", "rds_instance_deletion_protection", "rds_instance_storage_encrypted", "rds_instance_backup_enabled", "rds_instance_integration_cloudwatch_logs", "rds_instance_multi_az", "rds_instance_no_public_access", "rds_instance_storage_encrypted", "rds_snapshots_public_access", "redshift_cluster_automated_snapshot", "redshift_cluster_audit_logging", "redshift_cluster_public_access", "s3_bucket_default_encryption", "s3_bucket_secure_transport_policy", "s3_bucket_server_access_logging_enabled", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_bucket_object_versioning", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_training_jobs_volume_and_output_encryption_enabled", "sagemaker_notebook_instance_without_direct_internet_access_configured", "sagemaker_notebook_instance_encryption_enabled", "secretsmanager_automatic_rotation_enabled", "securityhub_enabled", "sns_topics_kms_encryption_at_rest_enabled", "vpc_endpoint_connections_trust_boundaries", "ec2_securitygroup_default_restrict_traffic", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_securitygroup_allow_ingress_from_internet_to_any_port"},
}
var cisa_your__urroundings_1 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your_-urroundings-1",
	Name:          "Your Surroundings-1",
	Description:   "Learn who is on your network. Maintain inventories of network connections (user accounts, vendors, business partners, etc.).",
	Section:       "your surroundings",
	Checks:        []string{"ec2_elastic_ip_unassigned", "vpc_flow_logs_enabled"},
}
var cisa_your_surroundings_2 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-surroundings-2",
	Name:          "Your Surroundings-2",
	Description:   "Leverage multi-factor authentication for all users, starting with privileged, administrative and remote access users.",
	Section:       "your surroundings",
	Checks:        []string{"iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access"},
}
var cisa_your_surroundings_3 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-surroundings-3",
	Name:          "Your Surroundings-3",
	Description:   "Grant access and admin permissions based on need-to-know and least privilege.",
	Section:       "your surroundings",
	Checks:        []string{"elbv2_ssl_listeners", "iam_no_custom_policy_permissive_role_assumption", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key"},
}
var cisa_your_surroundings_4 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-surroundings-4",
	Name:          "Your Surroundings-4",
	Description:   "Leverage unique passwords for all user accounts.",
	Section:       "your surroundings",
	Checks:        []string{"iam_password_policy_minimum_length_14", "iam_password_policy_lowercase", "iam_password_policy_number", "iam_password_policy_number", "iam_password_policy_symbol", "iam_password_policy_uppercase"},
}
var cisa_your_data_1 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-data-1",
	Name:          "Your Data-1",
	Description:   "Learn how your data is protected.",
	Section:       "your data",
	Checks:        []string{"efs_encryption_at_rest_enabled", "cloudtrail_kms_encryption_enabled", "dynamodb_tables_kms_cmk_encryption_enabled", "ec2_ebs_volume_encryption", "ec2_ebs_default_encryption", "opensearch_service_domains_encryption_at_rest_enabled", "rds_instance_storage_encrypted", "rds_instance_storage_encrypted", "redshift_cluster_audit_logging", "s3_bucket_default_encryption", "sagemaker_training_jobs_volume_and_output_encryption_enabled", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled"},
}
var cisa_your_data_2 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-data-2",
	Name:          "Your Data-2",
	Description:   "Learn what is happening on your network, manage network and perimeter components, host and device components, data-at-rest and in-transit, and user behavior activities.",
	Section:       "your data",
	Checks:        []string{"acm_certificates_expiration_check", "apigateway_restapi_client_certificate_enabled", "apigateway_restapi_logging_enabled", "efs_have_backup_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled", "cloudwatch_log_group_kms_encryption_enabled", "dynamodb_tables_kms_cmk_encryption_enabled", "ec2_ebs_volume_encryption", "ec2_instance_public_ip", "efs_encryption_at_rest_enabled", "elb_logging_enabled", "elbv2_waf_acl_attached", "elbv2_ssl_listeners", "elb_ssl_listeners", "emr_cluster_master_nodes_no_public_ip", "opensearch_service_domains_encryption_at_rest_enabled", "opensearch_service_domains_cloudwatch_logging_enabled", "opensearch_service_domains_node_to_node_encryption_enabled", "awslambda_function_not_publicly_accessible", "awslambda_function_not_publicly_accessible", "cloudwatch_log_group_kms_encryption_enabled", "rds_instance_storage_encrypted", "rds_instance_integration_cloudwatch_logs", "rds_instance_no_public_access", "rds_snapshots_public_access", "rds_snapshots_public_access", "redshift_cluster_audit_logging", "redshift_cluster_public_access", "s3_bucket_default_encryption", "s3_bucket_secure_transport_policy", "redshift_cluster_public_access", "s3_bucket_server_access_logging_enabled", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_acl_prohibited", "sagemaker_training_jobs_volume_and_output_encryption_enabled", "sagemaker_notebook_instance_without_direct_internet_access_configured", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled", "ec2_securitygroup_default_restrict_traffic", "vpc_flow_logs_enabled", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_securitygroup_allow_ingress_from_internet_to_any_port"},
}
var cisa_your_data_3 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-data-3",
	Name:          "Your Data-3",
	Description:   "Domain name system protection.",
	Section:       "your data",
	Checks:        []string{"elbv2_waf_acl_attached"},
}
var cisa_your_data_4 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-data-4",
	Name:          "Your Data-4",
	Description:   "Establish regular automated backups and redundancies of key systems.",
	Section:       "your data",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "elbv2_deletion_protection", "rds_instance_backup_enabled", "rds_instance_deletion_protection", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
var cisa_your_data_5 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-data-5",
	Name:          "Your Data-5",
	Description:   "Leverage protections for backups, including physical security, encryption and offline copies.",
	Section:       "your data",
	Checks:        []string{},
}
var cisa_your_crisis_response_2 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "your-crisis-response-2",
	Name:          "Your Crisis Response-2",
	Description:   "Lead development of an internal reporting structure to detect, communicate and contain attacks.",
	Section:       "your crisis response",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var cisa_booting_up_thing_to_do_first_1 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "booting-up-thing-to-do-first-1",
	Name:          "YBooting Up: Things to Do First-1",
	Description:   "Lead development of an internal reporting structure to detect, communicate and contain attacks.",
	Section:       "booting up thing to do first",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
var cisa_booting_up_thing_to_do_first_2 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "booting-up-thing-to-do-first-2",
	Name:          "YBooting Up: Things to Do First-2",
	Description:   "Require multi-factor authentication (MFA) for accessing your systems whenever possible. MFA should be required of all users, but start with privileged, administrative, and remote access users.",
	Section:       "booting up thing to do first",
	Checks:        []string{"iam_user_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "iam_user_hardware_mfa_enabled"},
}
var cisa_booting_up_thing_to_do_first_3 = &NistComp{
	Framework:     "CISA",
	Provider:      "AWS",
	Frameworkdesc: "Cybersecurity & Infrastructure Security Agency's (CISA) Cyber Essentials is a guide for leaders of small businesses as well as leaders of small and local government agencies to develop an actionable understanding of where to start implementing organizational cybersecurity practices.",
	Id:            "booting-up-thing-to-do-first-3",
	Name:          "YBooting Up: Things to Do First-3",
	Description:   "Enable automatic updates whenever possible. Replace unsupported operating systems, applications and hardware. Test and deploy patches quickly.",
	Section:       "booting up thing to do first",
	Checks:        []string{"rds_instance_minor_version_upgrade_enabled", "redshift_cluster_automatic_upgrades", "ssm_managed_compliant_patching"},
}
