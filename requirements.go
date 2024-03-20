package main

type NistComp struct {
	Provider string
	Framework string
	Frameworkdesc string
	Id string
	Name string
	Description string
	ItemId string
	Section string
	SubSection string
	Service string
	Type string
	Checks []string
}

	var FedRamp_Lowac_2 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "ac-2",
		Name: "Account Management (AC-2)",
		Description: "Manage system accounts, group memberships, privileges, workflow, notifications, deactivations, and authorizations.",
		Section: "Access Control (AC)",
		Checks: []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_log_file_validation_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "opensearch_service_domains_cloudwatch_logging_enabled", "guardduty_is_enabled", "iam_password_policy_minimum_length_14", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_no_root_access_key", "iam_rotate_access_key_90_days", "iam_user_mfa_enabled_console_access", "iam_user_hardware_mfa_enabled", "iam_user_accesskey_unused", "iam_user_console_access_unused", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "securityhub_enabled"},
	}
	var FedRamp_Lowac_3 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "ac-3",
		Name: "Account Management (AC-3)",
		Description: "The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
		Section: "Access Control (AC)",
		Checks: []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "ec2_instance_imdsv2_enabled", "emr_cluster_master_nodes_no_public_ip", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "iam_user_accesskey_unused", "iam_user_console_access_unused", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured"},
	}
	var FedRamp_Lowac_17 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "ac-17",
		Name: "Remote Access (AC-17)",
		Description: "Authorize remote access systems prior to connection. Enforce remote connection requirements to information systems.",
		Section: "Access Control (AC)",
		Checks: []string{"acm_certificates_expiration_check", "ec2_ebs_public_snapshot", "ec2_instance_public_ip", "elb_ssl_listeners", "emr_cluster_master_nodes_no_public_ip", "guardduty_is_enabled", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_secure_transport_policy", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "securityhub_enabled", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
	}
	var FedRamp_Lowau_2 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "au-2",
		Name: "Audit Events (AU-2)",
		Description: "The organization: a. Determines that the information system is capable of auditing the following events: [Assignment: organization-defined auditable events]; b. Coordinates the security audit function with other organizational entities requiring audit- related information to enhance mutual support and to help guide the selection of auditable events; c. Provides a rationale for why the auditable events are deemed to be adequate support after- the-fact investigations of security incidents",
		Section: "Audit and Accountability (AU)",
		Checks: []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_log_file_validation_enabled", "elbv2_logging_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
	}
	var FedRamp_Lowau_9 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "au-9",
		Name: "Protection of Audit Information (AU-9)",
		Description: "The information system protects audit information and audit tools from unauthorized access, modification, and deletion.",
		Section: "Audit and Accountability (AU)",
		Checks: []string{"cloudtrail_kms_encryption_enabled", "cloudtrail_log_file_validation_enabled", "cloudwatch_log_group_kms_encryption_enabled", "s3_bucket_object_versioning"},
	}
	var FedRamp_Lowau_11 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "au-11",
		Name: "Audit Record Retention (AU-11)",
		Description: "The organization retains audit records for at least 90 days to provide support for after-the-fact investigations of security incidents and to meet regulatory and organizational information retention requirements.",
		Section: "Audit and Accountability (AU)",
		Checks: []string{"cloudwatch_log_group_retention_policy_specific_days_enabled"},
	}
	var FedRamp_Lowca_7 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "ca-7",
		Name: "Continuous Monitoring (CA-7)",
		Description: "Continuously monitor configuration management processes. Determine security impact, environment and operational risks.",
		Section: "Security Assessment And Authorization (CA)",
		Checks: []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "ec2_instance_imdsv2_enabled", "elbv2_waf_acl_attached", "guardduty_is_enabled", "rds_instance_enhanced_monitoring_enabled", "redshift_cluster_audit_logging", "securityhub_enabled"},
	}
	var FedRamp_Lowcm_2 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "cm-2",
		Name: "Baseline Configuration (CM-2)",
		Description: "The organization develops, documents, and maintains under configuration control, a current baseline configuration of the information system.",
		Section: "Configuration Management (CM)",
		Checks: []string{"apigateway_restapi_waf_acl_attached", "ec2_ebs_public_snapshot", "ec2_instance_public_ip", "ec2_instance_older_than_specific_days", "elbv2_deletion_protection", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ssm_managed_compliant_patching", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
	}
	var FedRamp_Lowcm_8 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "cm-8",
		Name: "Information System Component Inventory (CM-8)",
		Description: "The organization develops and documents an inventory of information system components that accurately reflects the current information system, includes all components within the authorization boundary of the information system, is at the level of granularity deemed necessary for tracking and reporting and reviews and updates the information system component inventory.",
		Section: "Configuration Management (CM)",
		Checks: []string{"ec2_instance_managed_by_ssm", "guardduty_is_enabled", "ssm_managed_compliant_patching", "ssm_managed_compliant_patching"},
	}
	var FedRamp_Lowcp_9 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "cp-9",
		Name: "Information System Backup (CP-9)",
		Description: "The organization conducts backups of user-level information, system-level information and information system documentation including security-related documentation contained in the information system and protects the confidentiality, integrity, and availability of backup information at storage locations.",
		Section: "Contingency Planning (CP)",
		Checks: []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
	}
	var FedRamp_Lowcp_10 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "cp-10",
		Name: "Information System Recovery And Reconstitution (CP-10)",
		Description: "The organization provides for the recovery and reconstitution of the information system to a known state after a disruption, compromise, or failure.",
		Section: "Contingency Planning (CP)",
		Checks: []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "elbv2_deletion_protection", "rds_instance_backup_enabled", "rds_instance_multi_az", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
	}
	var FedRamp_Lowia_2 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "ia-2",
		Name: "Identification and Authentication (Organizational users) (IA-2)",
		Description: "The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).",
		Section: "Identification and Authentication (IA)",
		Checks: []string{"iam_password_policy_minimum_length_14", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_no_root_access_key", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access"},
	}
	var FedRamp_Lowir_4 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "ir-4",
		Name: "Incident Handling (IR-4)",
		Description: "The organization implements an incident handling capability for security incidents that includes preparation, detection and analysis, containment, eradication, and recovery, coordinates incident handling activities with contingency planning activities and incorporates lessons learned from ongoing incident handling activities into incident response procedures, training, and testing, and implements the resulting changes accordingly.",
		Section: "Incident Response (IR)",
		Checks: []string{"cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
	}
	var FedRamp_Lowsa_3 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "sa-3",
		Name: "System Development Life Cycle (SA-3)",
		Description: "The organization manages the information system using organization-defined system development life cycle, defines and documents information security roles and responsibilities throughout the system development life cycle, identifies individuals having information security roles and responsibilities and integrates the organizational information security risk management process into system development life cycle activities.",
		Section: "System and Services Acquisition (SA)",
		Checks: []string{"ec2_instance_managed_by_ssm"},
	}
	var FedRamp_Lowsc_5 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "sc-5",
		Name: "Denial Of Service Protection (SC-5)",
		Description: "The information system protects against or limits the effects of the following types of denial of service attacks: [Assignment: organization-defined types of denial of service attacks or references to sources for such information] by employing [Assignment: organization-defined security safeguards].",
		Section: "System and Communications Protection (SC)",
		Checks: []string{"dynamodb_tables_pitr_enabled", "elbv2_deletion_protection", "guardduty_is_enabled", "rds_instance_backup_enabled", "rds_instance_deletion_protection", "rds_instance_multi_az", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
	}
	var FedRamp_Lowsc_7 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "sc-7",
		Name: "Boundary Protection (SC-7)",
		Description: "The information system: a. Monitors and controls communications at the external boundary of the system and at key internal boundaries within the system; b. Implements subnetworks for publicly accessible system components that are [Selection: physically; logically] separated from internal organizational networks; and c. Connects to external networks or information systems only through managed interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.",
		Section: "System and Communications Protection (SC)",
		Checks: []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "elbv2_waf_acl_attached", "elb_ssl_listeners", "emr_cluster_master_nodes_no_public_ip", "opensearch_service_domains_node_to_node_encryption_enabled", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_secure_transport_policy", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
	}
	var FedRamp_Lowsc_12 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "sc-12",
		Name: "Cryptographic Key Establishment And Management (SC-12)",
		Description: "The organization establishes and manages cryptographic keys for required cryptography employed within the information system in accordance with [Assignment: organization-defined requirements for key generation, distribution, storage, access, and destruction].",
		Section: "System and Communications Protection (SC)",
		Checks: []string{"acm_certificates_expiration_check", "kms_cmk_rotation_enabled"},
	}
	var FedRamp_Lowsc_13 = &NistComp{
		Framework: "FedRAMP-Low-Revision-4",
		Provider: "AWS",
		Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
		Id: "sc-13",
		Name: "Use of Cryptography (SC-13)",
		Description: "The information system implements FIPS-validated or NSA-approved cryptography in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.",
		Section: "System and Communications Protection (SC)",
		Checks: []string{"s3_bucket_default_encryption", "sagemaker_training_jobs_volume_and_output_encryption_enabled", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled"},
	}
