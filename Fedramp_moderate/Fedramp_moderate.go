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

var FedRamp_Mod_ac_2_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-2-1",
	Name:          "AC-2(1) Automated System Account Management",
	Description:   "The organization employs automated mechanisms to support the management of information system accounts.",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"guardduty_is_enabled", "iam_password_policy_minimum_length_14", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_no_root_access_key", "iam_rotate_access_key_90_days", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access", "iam_user_accesskey_unused", "iam_user_console_access_unused", "securityhub_enabled"},
}
var FedRamp_Mod_ac_2_4 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-2-4",
	Name:          "AC-2(4) Automated Audit Actions",
	Description:   "The information system automatically audits account creation, modification, enabling, disabling, and removal actions, and notifies [Assignment: organization-defined personnel or roles].",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "guardduty_is_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "securityhub_enabled"},
}
var FedRamp_Mod_ac_2_12_a = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-2-12-a",
	Name:          "AC-2(12)(a)",
	Description:   "The organization: a. Monitors information system accounts for [Assignment: organization-defined atypical use].",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var FedRamp_Mod_ac_2_f = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-2-f",
	Name:          "AC-2(f)",
	Description:   "The organization: f. Creates, enables, modifies, disables, and removes information system accounts in accordance with [Assignment: organization-defined procedures or conditions].",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"iam_password_policy_minimum_length_14", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_no_root_access_key", "iam_rotate_access_key_90_days", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var FedRamp_Mod_ac_2_g = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-2-g",
	Name:          "AC-2(g)",
	Description:   "The organization: g. Monitors the use of information system accounts.",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "opensearch_service_domains_cloudwatch_logging_enabled", "guardduty_is_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "securityhub_enabled"},
}
var FedRamp_Mod_ac_2_j = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-2-j",
	Name:          "AC-2(j)",
	Description:   "The organization: j. Reviews accounts for compliance with account management requirements [Assignment: organization-defined frequency].",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"iam_password_policy_minimum_length_14", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_mfa_enabled", "iam_no_root_access_key", "iam_rotate_access_key_90_days", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var FedRamp_Mod_ac_2_3 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-2-3",
	Name:          "AC-2-3",
	Description:   "The information system automatically disables inactive accounts after 90 days for user accounts.",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"iam_password_policy_minimum_length_14", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var FedRamp_Mod_ac_3 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-3",
	Name:          "Access Enforcement (AC-3)",
	Description:   "The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
	Section:       "Access Control (AC)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "ec2_instance_imdsv2_enabled", "emr_cluster_master_nodes_no_public_ip", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "iam_user_accesskey_unused", "iam_user_console_access_unused", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured"},
}
var FedRamp_Mod_ac_4 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-4",
	Name:          "Information Flow Enforcement (AC-4)",
	Description:   "The information system enforces approved authorizations for controlling the flow of information within the system and between interconnected systems based on organization-defined information flow control policies.",
	Section:       "Access Control (AC)",
	Checks:        []string{"acm_certificates_expiration_check", "ec2_ebs_public_snapshot", "ec2_instance_public_ip", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FedRamp_Mod_ac_5_c = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-5-c",
	Name:          "AC-5(c)",
	Description:   "The organization: c. Defines information system access authorizations to support separation of duties.",
	Section:       "Access Control (AC)",
	SubSection:    "Separation Of Duties (AC-5)",
	Checks:        []string{"iam_password_policy_minimum_length_14", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var FedRamp_Mod_ac_6_10 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-6-10",
	Name:          "AC-6(10) Prohibit Non-Privileged Users From Executing Privileged Functions",
	Description:   "The information system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.",
	Section:       "Access Control (AC)",
	SubSection:    "Least Privilege (AC-6)",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key"},
}
var FedRamp_Mod_ac_6 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-6",
	Name:          "Least Privilege (AC-6)",
	Description:   "The organization employs the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) which are necessary to accomplish assigned tasks in accordance with organizational missions and business functions.",
	Section:       "Access Control (AC)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "ec2_instance_imdsv2_enabled", "emr_cluster_master_nodes_no_public_ip", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "iam_user_accesskey_unused", "iam_user_console_access_unused", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured"},
}
var FedRamp_Mod_ac_17_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-17-1",
	Name:          "AC-17(1) Automated Monitoring/Control",
	Description:   "The information system monitors and controls remote access methods.",
	Section:       "Access Control (AC)",
	SubSection:    "Remote Access (AC-17)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "emr_cluster_master_nodes_no_public_ip", "guardduty_is_enabled", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "securityhub_enabled", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FedRamp_Mod_ac_17_2 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-17-2",
	Name:          "AC-17(2) Protection Of Confidentiality/Integrity Using Encryption",
	Description:   "The information system implements cryptographic mechanisms to protect the confidentiality and integrity of remote access sessions.",
	Section:       "Access Control (AC)",
	SubSection:    "Remote Access (AC-17)",
	Checks:        []string{"acm_certificates_expiration_check", "elb_ssl_listeners", "s3_bucket_secure_transport_policy"},
}
var FedRamp_Mod_ac_21_b = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ac-21-b",
	Name:          "AC-21(b)",
	Description:   "The organization: b. Employs [Assignment: organization-defined automated mechanisms or manual processes] to assist users in making information sharing/collaboration decisions.",
	Section:       "Access Control (AC)",
	SubSection:    "Information Sharing (AC-21)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_networkacl_allow_ingress_any_port"},
}
var FedRamp_Mod_au_2_a_d = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "au-2-a-d",
	Name:          "AU-2(a)(d)",
	Description:   "The organization: a. Determines that the information system is capable of auditing the following events: Successful and unsuccessful account logon events, account management events, object access, policy change, privilege functions, process tracking, and system events. For Web applications: all administrator activity, authentication checks, authorization checks, data deletions, data access, data changes, and permission changes. d. Determines that the following events are to be audited within the information system: [organization-defined subset of the auditable events defined in AU-2 a to be audited continually for each identified event].",
	Section:       "Audit and Accountability (AU)",
	SubSection:    "Audit Events (AU-2)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var FedRamp_Mod_au_3 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "au-3",
	Name:          "Content of Audit Records (AU-3)",
	Description:   "The information system generates audit records containing information that establishes what type of event occurred, when the event occurred, where the event occurred, the source of the event, the outcome of the event, and the identity of any individuals or subjects associated with the event.",
	Section:       "Audit and Accountability (AU)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var FedRamp_Mod_au_6_1_3 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "au-6-1-3",
	Name:          "AU-6(1)(3)",
	Description:   "(1) The organization employs automated mechanisms to integrate audit review, analysis, and reporting processes to support organizational processes for investigation and response to suspicious activities. (3) The organization analyzes and correlates audit records across different repositories to gain organization-wide situational awareness.",
	Section:       "Audit and Accountability (AU)",
	SubSection:    "Audit Review, Analysis And Reporting (AU-6)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "cloudwatch_log_group_retention_policy_specific_days_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "guardduty_is_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
var FedRamp_Mod_au_7_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "au-7-1",
	Name:          "AU-7(1) Automatic Processing",
	Description:   "The information system provides the capability to process audit records for events of interest based on [Assignment: organization-defined audit fields within audit records].",
	Section:       "Audit and Accountability (AU)",
	SubSection:    "Audit Reduction And Report Generation (AU-7)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured"},
}
var FedRamp_Mod_au_9_2 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "au-9-2",
	Name:          "AU-9(2) Audit Backup On Separate Physical Systems / Components",
	Description:   "The information system backs up audit records at least weekly onto a physically different system or system component than the system or component being audited.",
	Section:       "Audit and Accountability (AU)",
	SubSection:    "Protection of Audit Information (AU-9)",
	Checks:        []string{"s3_bucket_object_versioning"},
}
var FedRamp_Mod_au_9 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "au-9",
	Name:          "Protection of Audit Information (AU-9)",
	Description:   "The information system protects audit information and audit tools from unauthorized access, modification, and deletion.",
	Section:       "Audit and Accountability (AU)",
	Checks:        []string{"cloudtrail_kms_encryption_enabled", "cloudtrail_log_file_validation_enabled", "cloudwatch_log_group_kms_encryption_enabled"},
}
var FedRamp_Mod_au_11 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "au-11",
	Name:          "Audit Record Retention (AU-11)",
	Description:   "The organization retains audit records for at least 90 days to provide support for after-the-fact investigations of security incidents and to meet regulatory and organizational information retention requirements.",
	Section:       "Audit and Accountability (AU)",
	Checks:        []string{"cloudwatch_log_group_retention_policy_specific_days_enabled"},
}
var FedRamp_Mod_au_12_a_c = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "au-12-a-c",
	Name:          "AU-12(a)(c)",
	Description:   "The information system: a. Provides audit record generation capability for the auditable events defined in AU-2 a. at all information system and network components where audit capability is deployed/available c. Generates audit records for the events defined in AU-2 d. with the content defined in AU-3.",
	Section:       "Audit and Accountability (AU)",
	SubSection:    "Audit Generation (AU-12)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var FedRamp_Mod_ca_7_a_b = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ca-7-a-b",
	Name:          "CA-7(a)(b)",
	Description:   "The organization develops a continuous monitoring strategy and implements a continuous monitoring program that includes: a. Establishment of [Assignment: organization-defined metrics] to be monitored; b. Establishment of [Assignment: organization-defined frequencies] for monitoring and [Assignment: organization-defined frequencies] for assessments supporting such monitoring.",
	Section:       "Security Assessment And Authorization (CA)",
	SubSection:    "Continuous Monitoring (CA-7)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "guardduty_is_enabled", "rds_instance_enhanced_monitoring_enabled", "redshift_cluster_audit_logging", "securityhub_enabled"},
}
var FedRamp_Mod_cm_2 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "cm-2",
	Name:          "Baseline Configuration (CM-2)",
	Description:   "The organization develops, documents, and maintains under configuration control, a current baseline configuration of the information system.",
	Section:       "Configuration Management (CM)",
	Checks:        []string{"apigateway_restapi_waf_acl_attached", "ec2_ebs_public_snapshot", "ec2_instance_public_ip", "ec2_instance_managed_by_ssm", "ec2_instance_older_than_specific_days", "elbv2_waf_acl_attached", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ssm_managed_compliant_patching", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FedRamp_Mod_cm_7_a = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "cm-7-a",
	Name:          "CM-7(a)",
	Description:   "The organization: a. Configures the information system to provide only essential capabilities.",
	Section:       "Configuration Management (CM)",
	SubSection:    "Least Functionality (CM-7)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching"},
}
var FedRamp_Mod_cm_8_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "cm-8-1",
	Name:          "CM-8(1)",
	Description:   "The organization updates the inventory of information system components as an integral part of component installations, removals, and information system updates.",
	Section:       "Configuration Management (CM)",
	SubSection:    "Information System Component Inventory (CM-8)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching"},
}
var FedRamp_Mod_cm_8_3_a = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "cm-8-3-a",
	Name:          "CM-8(3)(a)",
	Description:   "The organization: a. Employs automated mechanisms continuously, using automated mechanisms with a maximum five-minute delay in detection, to detect the presence of unauthorized hardware, software, and firmware components within the information system",
	Section:       "Configuration Management (CM)",
	SubSection:    "Information System Component Inventory (CM-8)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "guardduty_is_enabled", "ssm_managed_compliant_patching", "ssm_managed_compliant_patching"},
}
var FedRamp_Mod_cp_9_b = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "cp-9-b",
	Name:          "CP-9(b))",
	Description:   "The organization: b. Conducts backups of system-level information contained in the information system (daily incremental; weekly full).",
	Section:       "Contingency Planning (CP)",
	SubSection:    "Information System Backup (CP-9)",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
var FedRamp_Mod_cp_10 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "cp-10",
	Name:          "Information System Recovery And Reconstitution (CP-10)",
	Description:   "The organization provides for the recovery and reconstitution of the information system to a known state after a disruption, compromise, or failure.",
	Section:       "Contingency Planning (CP)",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "elbv2_deletion_protection", "rds_instance_backup_enabled", "rds_instance_multi_az", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
var FedRamp_Mod_ia_2_1_2 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ia-2-1-2",
	Name:          "IA-2(1)(2)",
	Description:   "(1) The information system implements multifactor authentication for network access to privileged accounts. (2) The information system implements multifactor authentication for network access to non- privileged accounts.",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "IA-2(1) Network Access To Privileged Accounts",
	Checks:        []string{"iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access", "iam_root_hardware_mfa_enabled"},
}
var FedRamp_Mod_ia_2_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ia-2-1",
	Name:          "IA-2(1) Network Access To Privileged Accounts",
	Description:   "The information system implements multi-factor authentication for network access to privileged accounts.",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "Identification and Authentication (Organizational users) (IA-2)",
	Checks:        []string{"iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access"},
}
var FedRamp_Mod_ia_2 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ia-2",
	Name:          "Identification and Authentication (Organizational users) (IA-2)",
	Description:   "The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).",
	Section:       "Identification and Authentication (IA)",
	Checks:        []string{"iam_password_policy_minimum_length_14", "iam_no_root_access_key"},
}
var FedRamp_Mod_ia_5_1_a_d_e = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ia-5-1-a-d-e",
	Name:          "IA-5(1)(a)(d)(e)",
	Description:   "The information system, for password-based authentication: a. Enforces minimum password complexity of [Assignment: organization-defined requirements for case sensitivity, number of characters, mix of upper-case letters, lower-case letters, numbers, and special characters, including minimum requirements for each type]; d. Enforces password minimum and maximum lifetime restrictions of [Assignment: organization- defined numbers for lifetime minimum, lifetime maximum]; e. Prohibits password reuse for 24 generations",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "IA-5(1) Password-Based Authentication",
	Checks:        []string{"iam_password_policy_minimum_length_14"},
}
var FedRamp_Mod_ia_5_4 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ia-5-4",
	Name:          "IA-5(4) Automated Support For Password Strength Determination",
	Description:   "The organization employs automated tools to determine if password authenticators are sufficiently strong to satisfy [Assignment: organization-defined requirements].",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "Authenticator Management (IA-5)",
	Checks:        []string{"iam_password_policy_minimum_length_14"},
}
var FedRamp_Mod_ia_5_7 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ia-5-7",
	Name:          "IA-5(7) No Embedded Unencrypted Static Authenticators",
	Description:   "The organization ensures that unencrypted static authenticators are not embedded in applications or access scripts or stored on function keys.",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "Authenticator Management (IA-5)",
	Checks:        []string{},
}
var FedRamp_Mod_ir_4_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ir-4-1",
	Name:          "IR-4(1) Automated Incident Handling Processes",
	Description:   "The organization employs automated mechanisms to support the incident handling process.",
	Section:       "Incident Response (IR)",
	SubSection:    "Incident Handling (IR-4)",
	Checks:        []string{"cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}

var FedRamp_Mod_ir_6_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ir-6-1",
	Name:          "IR-6(1) Automated Reporting",
	Description:   "The organization employs automated mechanisms to assist in the reporting of security incidents.",
	Section:       "Incident Response (IR)",
	SubSection:    "Incident Reporting (IR-6)",
	Checks:        []string{"guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var FedRamp_Mod_ir_7_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ir-7-1",
	Name:          "IR-7(1) Automation Support For Availability Of Information / Support",
	Description:   "The organization employs automated mechanisms to increase the availability of incident response-related information and support.",
	Section:       "Incident Response (IR)",
	SubSection:    "Incident Response Assistance (IR-7)",
	Checks:        []string{"guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var FedRamp_Mod_ra_5 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "ra-5",
	Name:          "Vulnerability Scanning (RA-5)",
	Description:   "Scan for system vulnerabilities. Share vulnerability information and security controls that eliminate vulnerabilities.",
	Section:       "Risk Assessment (RA)",
	Checks:        []string{"guardduty_is_enabled", "guardduty_no_high_severity_findings"},
}
var FedRamp_Mod_sa_3_a = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sa-3-a",
	Name:          "SA-3(a)",
	Description:   "The organization: a. Manages the information system using [Assignment: organization-defined system development life cycle] that incorporates information security considerations.",
	Section:       "System and Services Acquisition (SA)",
	SubSection:    "System Development Life Cycle (SA-3)",
	Checks:        []string{"ec2_instance_managed_by_ssm"},
}
var FedRamp_Mod_sa_10 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sa-10",
	Name:          "Developer Configuration Management (SA-10)",
	Description:   "The organization requires the developer of the information system, system component, or information system service to: a. Perform configuration management during system, component, or service [Selection (one or more): design; development; implementation; operation]; b. Document, manage, and control the integrity of changes to [Assignment: organization-defined configuration items under configuration management]; c. Implement only organization-approved changes to the system, component, or service; d. Document approved changes to the system, component, or service and the potential security impacts of such changes; and e. Track security flaws and flaw resolution within the system, component, or service and report findings to [Assignment: organization-defined personnel].",
	Section:       "System and Services Acquisition (SA)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var FedRamp_Mod_sc_2 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-2",
	Name:          "Application Partitioning (SC-2)",
	Description:   "The information system separates user functionality (including user interface services) from information system management functionality.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges"},
}
var FedRamp_Mod_sc_4 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-4",
	Name:          "Information In Shared Resources (SC-4)",
	Description:   "The information system prevents unauthorized and unintended information transfer via shared system resources.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"ec2_ebs_public_snapshot", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FedRamp_Mod_sc_5 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-5",
	Name:          "Denial Of Service Protection (SC-5)",
	Description:   "The information system protects against or limits the effects of the following types of denial of service attacks: [Assignment: organization-defined types of denial of service attacks or references to sources for such information] by employing [Assignment: organization-defined security safeguards].",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"rds_instance_deletion_protection", "dynamodb_tables_pitr_enabled", "elbv2_deletion_protection", "guardduty_is_enabled", "rds_instance_multi_az", "s3_bucket_object_versioning"},
}
var FedRamp_Mod_sc_7_3 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-7-3",
	Name:          "SC-7(3) Access Points",
	Description:   "The organization limits the number of external network connections to the information system.",
	Section:       "System and Communications Protection (SC)",
	SubSection:    "Boundary Protection (SC-7)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FedRamp_Mod_sc_7 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-7",
	Name:          "Boundary Protection (SC-7)",
	Description:   "The information system: a. Monitors and controls communications at the external boundary of the system and at key internal boundaries within the system; b. Implements subnetworks for publicly accessible system components that are [Selection: physically; logically] separated from internal organizational networks; and c. Connects to external networks or information systems only through managed interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "elbv2_waf_acl_attached", "elb_ssl_listeners", "emr_cluster_master_nodes_no_public_ip", "opensearch_service_domains_node_to_node_encryption_enabled", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_secure_transport_policy", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FedRamp_Mod_sc_8_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-8-1",
	Name:          "SC-8(1) Cryptographic Or Alternate Physical Protection",
	Description:   "The information system implements cryptographic mechanisms to [Selection (one or more): prevent unauthorized disclosure of information; detect changes to information] during transmission unless otherwise protected by [Assignment: organization-defined alternative physical safeguards].",
	Section:       "System and Communications Protection (SC)",
	SubSection:    "Transmission Integrity (SC-8)",
	Checks:        []string{"apigateway_restapi_client_certificate_enabled", "elbv2_insecure_ssl_ciphers", "elb_ssl_listeners", "opensearch_service_domains_node_to_node_encryption_enabled", "s3_bucket_secure_transport_policy"},
}
var FedRamp_Mod_sc_8 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-8",
	Name:          "Transmission Integrity (SC-8)",
	Description:   "The information system protects the confidentiality AND integrity of transmitted information.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"apigateway_restapi_client_certificate_enabled", "elbv2_insecure_ssl_ciphers", "elb_ssl_listeners", "opensearch_service_domains_node_to_node_encryption_enabled", "s3_bucket_secure_transport_policy"},
}
var FedRamp_Mod_sc_12 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-12",
	Name:          "Cryptographic Key Establishment And Management (SC-12)",
	Description:   "The organization establishes and manages cryptographic keys for required cryptography employed within the information system in accordance with [Assignment: organization-defined requirements for key generation, distribution, storage, access, and destruction].",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"acm_certificates_expiration_check", "kms_cmk_rotation_enabled"},
}
var FedRamp_Mod_sc_13 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-13",
	Name:          "Use of Cryptography (SC-13)",
	Description:   "The information system implements FIPS-validated or NSA-approved cryptography in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"s3_bucket_default_encryption", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled"},
}
var FedRamp_Mod_sc_23 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-23",
	Name:          "Session Authenticity (SC-23)",
	Description:   "The information system protects the authenticity of communications sessions.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"apigateway_restapi_client_certificate_enabled", "elb_ssl_listeners", "opensearch_service_domains_node_to_node_encryption_enabled", "s3_bucket_secure_transport_policy"},
}
var FedRamp_Mod_sc_28 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "sc-28",
	Name:          "Protection of Information at Rest (SC-28)",
	Description:   "The information system protects the confidentiality AND integrity of [Assignment: organization-defined information at rest].",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"cloudtrail_kms_encryption_enabled", "ec2_ebs_volume_encryption", "ec2_ebs_volume_encryption", "efs_encryption_at_rest_enabled", "opensearch_service_domains_encryption_at_rest_enabled", "cloudwatch_log_group_kms_encryption_enabled", "rds_instance_storage_encrypted", "rds_instance_storage_encrypted", "redshift_cluster_audit_logging", "s3_bucket_default_encryption", "s3_bucket_default_encryption", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled"},
}
var FedRamp_Mod_si_2_2 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "si-2-2",
	Name:          "Automated Flaw Remediation Status (SI-2(2))",
	Description:   "The organization employs automated mechanisms at least monthly to determine the state of information system components with regard to flaw remediation.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Flaw Remediation (SI-2)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching", "ssm_managed_compliant_patching"},
}
var FedRamp_Mod_si_4_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "si-4-1",
	Name:          "SI-4(1) System-Wide Intrusion Detection System",
	Description:   "The organization connects and configures individual intrusion detection tools into an information system-wide intrusion detection system.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"guardduty_is_enabled"},
}
var FedRamp_Mod_si_4_16 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "si-4-16",
	Name:          "SI-4(16) Correlate Monitoring Information",
	Description:   "The organization correlates information from monitoring tools employed throughout the information system.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "guardduty_is_enabled", "redshift_cluster_audit_logging", "securityhub_enabled"},
}
var FedRamp_Mod_si_4_2 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "si-4-2",
	Name:          "SI-4(2) Automated Tools For Real-Time Analysis",
	Description:   "The organization employs automated tools to support near real-time analysis of events.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "guardduty_is_enabled", "redshift_cluster_audit_logging", "securityhub_enabled"},
}
var FedRamp_Mod_si_4_4 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "si-4-4",
	Name:          "SI-4(4) Inbound and Outbound Communications Traffic",
	Description:   "The information system monitors inbound and outbound communications traffic continuously for unusual or unauthorized activities or conditions.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "guardduty_is_enabled", "redshift_cluster_audit_logging", "securityhub_enabled"},
}
var FedRamp_Mod_si_4_5 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "si-4-5",
	Name:          "SI-4(5) System-Generated Alerts",
	Description:   "The information system alerts organization-defined personnel or roles when the following indications of compromise or potential compromise occur: [Assignment: organization-defined compromise indicators].",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "guardduty_is_enabled", "redshift_cluster_audit_logging", "securityhub_enabled"},
}
var FedRamp_Mod_si_4_a_b_c = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "si-4-a-b-c",
	Name:          "SI-4(a)(b)(c)",
	Description:   "The organization: a. Monitors the information system to detect: 1. Attacks and indicators of potential attacks in accordance with [Assignment: organization- defined monitoring objectives]; and 2. Unauthorized local, network, and remote connections; b. Identifies unauthorized use of the information system through [Assignment: organization- defined techniques and methods]; c. Deploys monitoring devices: i. strategically within the information system to collect organization-determined essential information; and (ii) at ad hoc locations within the system to track specific types of transactions of interest to the organization.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"apigateway_restapi_waf_acl_attached", "cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "elbv2_waf_acl_attached", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var FedRamp_Mod_si_7_1 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "si-7-1",
	Name:          "SI-7(1) Integrity Checks",
	Description:   "The information system performs an integrity check of security relevant events at least monthly.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Software, Firmware, and Information Integrity (SI-7)",
	Checks:        []string{"cloudtrail_log_file_validation_enabled", "ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching"},
}
var FedRamp_Mod_si_7 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "si-7",
	Name:          "Software, Firmware, and Information Integrity (SI-7)",
	Description:   "The organization employs integrity verification tools to detect unauthorized changes to [Assignment: organization-defined software, firmware, and information].",
	Section:       "System and Information Integrity (SI)",
	Checks:        []string{"cloudtrail_log_file_validation_enabled"},
}
var FedRamp_Mod_si_12 = &NistComp{
	Framework:     "FedRamp-Moderate-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "The Federal Risk and Authorization Management Program (FedRAMP) was established in 2011. It provides a cost-effective, risk-based approach for the adoption and use of cloud services by the U.S. federal government. FedRAMP empowers federal agencies to use modern cloud technologies, with an emphasis on the security and protection of federal information.",
	Id:            "si-12",
	Name:          "Information Handling and Retention (SI-12)",
	Description:   "The organization handles and retains information within the information system and information output from the system in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and operational requirements.",
	Section:       "System and Information Integrity (SI)",
	Checks:        []string{"cloudwatch_log_group_retention_policy_specific_days_enabled", "dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
