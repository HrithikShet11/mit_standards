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

var nist_4_ac_2_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_2_1",
	Name:          "AC-2(1) Automated System Account Management",
	Description:   "Access control policies (e.g., identity or role-based policies, control matrices, and cryptography) control access between active entities or subjects (i.e., users or processes acting on behalf of users) and passive entities or objects (e.g., devices, files, records, and domains) in systems. Access enforcement mechanisms can be employed at the application and service level to provide increased information security. Other systems include systems internal and external to the organization. This requirement focuses on account management for systems and applications. The definition of and enforcement of access authorizations, other than those determined by account type (e.g., privileged verses non-privileged) are addressed in requirement 3.1.2.",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"guardduty_is_enabled", "iam_password_policy_reuse_24", "iam_rotate_access_key_90_days", "iam_user_accesskey_unused", "iam_user_console_access_unused", "securityhub_enabled"},
}
var nist_4_ac_2_3 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_2_3",
	Name:          "AC-2(3) Disable Inactive Accounts",
	Description:   "The information system automatically disables inactive accounts after 90 days for user accounts.",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var nist_4_ac_2_4 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_2_4",
	Name:          "AC-2(4) Automated Audit Actions",
	Description:   "The information system automatically audits account creation, modification, enabling, disabling, and removal actions, and notifies [Assignment: organization-defined personnel or roles].",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "guardduty_is_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "securityhub_enabled"},
}
var nist_4_ac_2_12 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_2_12",
	Name:          "AC-2(12) Account Monitoring",
	Description:   "Monitors and reports atypical usage of information system accounts to organization-defined personnel or roles.",
	Section:       "Access Control (AC)",
	SubSection:    "Account Management (AC-2)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var nist_4_ac_2 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_2",
	Name:          "Account Management (AC-2)",
	Description:   "Manage system accounts, group memberships, privileges, workflow, notifications, deactivations, and authorizations.",
	Section:       "Access Control (AC)",
	Checks:        []string{"cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "guardduty_is_enabled", "iam_password_policy_reuse_24", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_mfa_enabled", "iam_no_root_access_key", "iam_rotate_access_key_90_days", "iam_user_accesskey_unused", "iam_user_console_access_unused", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "securityhub_enabled"},
}
var nist_4_ac_3 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_3",
	Name:          "Access Enforcement (AC-3)",
	Description:   "The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
	Section:       "Access Control (AC)",
	Checks:        []string{"ec2_ebs_public_snapshot", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "iam_user_accesskey_unused", "iam_user_console_access_unused", "awslambda_function_url_public", "rds_snapshots_public_access", "redshift_cluster_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_bucket_public_access"},
}
var nist_4_ac_4 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_4",
	Name:          "Information Flow Enforcement (AC-4)",
	Description:   "The information system enforces approved authorizations for controlling the flow of information within the system and between interconnected systems based on organization-defined information flow control policies.",
	Section:       "Access Control (AC)",
	Checks:        []string{"acm_certificates_expiration_check", "ec2_ebs_public_snapshot", "ec2_instance_public_ip", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var nist_4_ac_5 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_5",
	Name:          "Separation Of Duties (AC-5)",
	Description:   "Separate duties of individuals to prevent malevolent activity. automate separation of duties and access authorizations.",
	Section:       "Access Control (AC)",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges"},
}
var nist_4_ac_6_10 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_6_10",
	Name:          "AC-6(10) Prohibit Non-Privileged Users From Executing Privileged Functions",
	Description:   "The information system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.",
	Section:       "Access Control (AC)",
	SubSection:    "Least Privilege (AC-6)",
	Checks:        []string{"iam_no_root_access_key"},
}
var nist_4_ac_6 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_6",
	Name:          "Least Privilege (AC-6)",
	Description:   "The organization employs the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) which are necessary to accomplish assigned tasks in accordance with organizational missions and business functions.",
	Section:       "Access Control (AC)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "ec2_instance_imdsv2_enabled", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "iam_user_accesskey_unused", "iam_user_console_access_unused", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured"},
}
var nist_4_ac_17_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_17_1",
	Name:          "AC-17(1) Automated Monitoring/Control",
	Description:   "The information system monitors and controls remote access methods.",
	Section:       "Access Control (AC)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var nist_4_ac_17_2 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_17_2",
	Name:          "AC-17(2) Protection Of Confidentiality/Integrity Using Encryption",
	Description:   "The information system implements cryptographic mechanisms to protect the confidentiality and integrity of remote access sessions.",
	Section:       "Access Control (AC)",
	Checks:        []string{"acm_certificates_expiration_check", "elb_ssl_listeners", "s3_bucket_secure_transport_policy"},
}
var nist_4_ac_17_3 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_17_3",
	Name:          "AC-17(3) Managed Access Control Points",
	Description:   "The information system routes all remote accesses through organization-defined managed network access control points.",
	Section:       "Access Control (AC)",
	Checks:        []string{},
}
var nist_4_ac_21 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ac_21",
	Name:          "Information Sharing (AC-21)",
	Description:   "Facilitate information sharing. Enable authorized users to grant access to partners.",
	Section:       "Access Control (AC)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured"},
}
var nist_4_au_2 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "au_2",
	Name:          "Event Logging (AU-2)",
	Description:   "Automate security audit function with other organizational entities. Enable mutual support of audit of auditable events.",
	Section:       "Audit and Accountability (AU)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var nist_4_au_3 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "au_3",
	Name:          "Content of Audit Records (AU-3)",
	Description:   "The information system generates audit records containing information that establishes what type of event occurred, when the event occurred, where the event occurred, the source of the event, the outcome of the event, and the identity of any individuals or subjects associated with the event.",
	Section:       "Audit and Accountability (AU)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var nist_4_au_6_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "au_6_1",
	Name:          "AU-6(1) Process Integration",
	Description:   "The organization employs automated mechanisms to integrate audit review, analysis,and reporting processes to support organizational processes for investigation and response to suspicious activities.",
	Section:       "Audit and Accountability (AU)",
	SubSection:    "Audit Review, Analysis And Reporting (AU-6)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "guardduty_is_enabled", "securityhub_enabled"},
}
var nist_4_au_6_3 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "au_6_3",
	Name:          "AU-6(3) Correlate Audit Repositories",
	Description:   "The organization analyzes and correlates audit records across different repositories to gain organization-wide situational awareness.",
	Section:       "Audit and Accountability (AU)",
	SubSection:    "Audit Review, Analysis And Reporting (AU-6)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "guardduty_is_enabled", "securityhub_enabled"},
}
var nist_4_au_7_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "au_7_1",
	Name:          "AU-7(1) Automatic Processing",
	Description:   "The information system provides the capability to process audit records for events of interest based on [Assignment: organization-defined audit fields within audit records].",
	Section:       "Audit and Accountability (AU)",
	Checks:        []string{"cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "cloudtrail_cloudwatch_logging_enabled"},
}
var nist_4_au_9_2 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "au_9_2",
	Name:          "AU-9(2) Audit Backup On Separate Physical Systems / Components",
	Description:   "The information system backs up audit records [Assignment: organization-defined frequency] onto a physically different system or system component than the system or component being audited.",
	Section:       "Audit and Accountability (AU)",
	SubSection:    "Protection of Audit Information (AU-9)",
	Checks:        []string{},
}
var nist_4_au_9 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "au_9",
	Name:          "Protection of Audit Information (AU-9)",
	Description:   "The information system protects audit information and audit tools from unauthorized access, modification, and deletion.",
	Section:       "Audit and Accountability (AU)",
	Checks:        []string{"cloudtrail_kms_encryption_enabled", "cloudwatch_log_group_kms_encryption_enabled"},
}
var nist_4_au_11 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "au_11",
	Name:          "Audit Record Retention (AU-11)",
	Description:   "The organization retains audit records for [Assignment: organization-defined time period consistent with records retention policy] to provide support for after-the-fact investigations of security incidents and to meet regulatory and organizational information retention requirements.",
	Section:       "Audit and Accountability (AU)",
	Checks:        []string{"cloudwatch_log_group_retention_policy_specific_days_enabled"},
}
var nist_4_au_12 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "au_12",
	Name:          "Audit Generation (AU-12)",
	Description:   "Audit events defined in AU-2. Allow trusted personnel to select which events to audit. Generate audit records for events.",
	Section:       "Audit and Accountability (AU)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var nist_4_ca_7 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ca_7",
	Name:          "Continuous Monitoring (CA-7)",
	Description:   "Continuously monitor configuration management processes. Determine security impact, environment and operational risks.",
	Section:       "Security Assessment And Authorization (CA)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "guardduty_is_enabled", "rds_instance_enhanced_monitoring_enabled", "securityhub_enabled"},
}
var nist_4_cm_2 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "cm_2",
	Name:          "Baseline Configuration (CM-2)",
	Description:   "The organization develops, documents, and maintains under configuration control, a current baseline configuration of the information system.",
	Section:       "Configuration Management (CM)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "ec2_instance_managed_by_ssm", "ec2_instance_older_than_specific_days", "elbv2_deletion_protection", "ssm_managed_compliant_patching", "ec2_networkacl_allow_ingress_any_port"},
}
var nist_4_cm_7 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "cm_7",
	Name:          "Least Functionality (CM-7)",
	Description:   "The organization configures the information system to provide only essential capabilities and prohibits or restricts the use of the functions, ports, protocols, and/or services.",
	Section:       "Configuration Management (CM)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching"},
}
var nist_4_cm_8_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "cm_8_1",
	Name:          "CM-8(1) Updates During Installation / Removals",
	Description:   "The organization develops and documents an inventory of information system components that accurately reflects the current information system, includes all components within the authorization boundary of the information system, is at the level of granularity deemed necessary for tracking and reporting and reviews and updates the information system component inventory.",
	Section:       "Configuration Management (CM)",
	SubSection:    "Information System Component Inventory (CM-8)",
	Checks:        []string{"ec2_instance_managed_by_ssm"},
}
var nist_4_cm_8_3 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "cm_8_3",
	Name:          "CM-8(3) Automated Unauthorized Component Detection",
	Description:   "The organization employs automated mechanisms to detect the presence of unauthorized hardware, software, and firmware components within the information system and takes actions (disables network access by such components, isolates the components etc) when unauthorized components are detected.",
	Section:       "Configuration Management (CM)",
	SubSection:    "Information System Component Inventory (CM-8)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching", "ssm_managed_compliant_patching"},
}
var nist_4_cp_9 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "cp_9",
	Name:          "Information System Backup (CP-9)",
	Description:   "The organization conducts backups of user-level information, system-level information and information system documentation including security-related documentation contained in the information system and protects the confidentiality, integrity, and availability of backup information at storage locations.",
	Section:       "Contingency Planning (CP)",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled"},
}
var nist_4_cp_10 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "cp_10",
	Name:          "Information System Recovery And Reconstitution (CP-10)",
	Description:   "The organization provides for the recovery and reconstitution of the information system to a known state after a disruption, compromise, or failure.",
	Section:       "Contingency Planning (CP)",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "elbv2_deletion_protection", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "rds_instance_multi_az", "s3_bucket_object_versioning"},
}
var nist_4_ia_2_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ia_2_1",
	Name:          "IA-2(1) Network Access To Privileged Accounts",
	Description:   "The information system implements multi-factor authentication for network access to privileged accounts.",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "Identification and Authentication (Organizational users) (IA-2)",
	Checks:        []string{"iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access"},
}
var nist_4_ia_2_2 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ia_2_2",
	Name:          "IA-2(2) Network Access To Non-Privileged Accounts",
	Description:   "The information system implements multifactor authentication for network access to non-privileged accounts.",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "Identification and Authentication (Organizational users) (IA-2)",
	Checks:        []string{"iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access"},
}
var nist_4_ia_2_11 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ia_2_11",
	Name:          "IA-2(11) Remote Access - Separate Device",
	Description:   "The information system implements multifactor authentication for remote access to privileged and non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access and the device meets [Assignment: organization-defined strength of mechanism requirements].",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "Identification and Authentication (Organizational users) (IA-2)",
	Checks:        []string{"iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access"},
}
var nist_4_ia_2 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ia_2",
	Name:          "Identification and Authentication (Organizational users) (IA-2)",
	Description:   "The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).",
	Section:       "Identification and Authentication (IA)",
	Checks:        []string{"iam_password_policy_reuse_24"},
}
var nist_4_ia_5_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ia_5_1",
	Name:          "IA-5(1) Password-Based Authentication",
	Description:   "The information system, for password-based authentication that enforces minimum password complexity, stores and transmits only cryptographically-protected passwords, enforces password minimum and maximum lifetime restrictions, prohibits password reuse, allows the use of a temporary password for system logons with an immediate change to a permanent password etc.",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "Authenticator Management (IA-5)",
	Checks:        []string{"iam_password_policy_reuse_24"},
}
var nist_4_ia_5_4 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ia_5_4",
	Name:          "IA-5(4) Automated Support For Password Strength Determination",
	Description:   "The organization employs automated tools to determine if password authenticators are sufficiently strong to satisfy [Assignment: organization-defined requirements].",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "Authenticator Management (IA-5)",
	Checks:        []string{"iam_password_policy_reuse_24"},
}
var nist_4_ia_5_7 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ia_5_7",
	Name:          "IA-5(7) No Embedded Unencrypted Static Authenticators",
	Description:   "The organization ensures that unencrypted static authenticators are not embedded in applications or access scripts or stored on function keys.",
	Section:       "Identification and Authentication (IA)",
	SubSection:    "Authenticator Management (IA-5)",
	Checks:        []string{},
}
var nist_4_ir_4_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ir_4_1",
	Name:          "IR-4(1) Automated Incident Handling Processes",
	Description:   "The organization employs automated mechanisms to support the incident handling process.",
	Section:       "Incident Response (IR)",
	SubSection:    "Incident Handling (IR-4)",
	Checks:        []string{"cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "guardduty_no_high_severity_findings"},
}
var nist_4_ir_6_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ir_6_1",
	Name:          "IR-6(1) Automated Reporting",
	Description:   "The organization employs automated mechanisms to assist in the reporting of security incidents.",
	Section:       "Incident Response (IR)",
	SubSection:    "Incident Reporting (IR-6)",
	Checks:        []string{"guardduty_no_high_severity_findings"},
}
var nist_4_ir_7_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ir_7_1",
	Name:          "IR-7(1) Automation Support For Availability Of Information / Support",
	Description:   "The organization employs automated mechanisms to increase the availability of incident response-related information and support.",
	Section:       "Incident Response (IR)",
	SubSection:    "Incident Response Assistance (IR-7)",
	Checks:        []string{"guardduty_no_high_severity_findings"},
}
var nist_4_ra_5 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "ra_5",
	Name:          "Vulnerability Scanning (RA-5)",
	Description:   "Scan for system vulnerabilities. Share vulnerability information and security controls that eliminate vulnerabilities.",
	Section:       "Risk Assessment (RA)",
	Checks:        []string{"guardduty_is_enabled", "guardduty_no_high_severity_findings"},
}
var nist_4_sa_3 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sa_3",
	Name:          "System Development Life Cycle (SA-3)",
	Description:   "The organization manages the information system using organization-defined system development life cycle, defines and documents information security roles and responsibilities throughout the system development life cycle, identifies individuals having information security roles and responsibilities and integrates the organizational information security risk management process into system development life cycle activities.",
	Section:       "System and Services Acquisition (SA)",
	Checks:        []string{"ec2_instance_managed_by_ssm"},
}
var nist_4_sa_10 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sa_10",
	Name:          "Developer Configuration Management (SA-10)",
	Description:   "The organization requires the developer of the information system, system component, or information system service to: a. Perform configuration management during system, component, or service [Selection (one or more): design; development; implementation; operation]; b. Document, manage, and control the integrity of changes to [Assignment: organization-defined configuration items under configuration management]; c. Implement only organization-approved changes to the system, component, or service; d. Document approved changes to the system, component, or service and the potential security impacts of such changes; and e. Track security flaws and flaw resolution within the system, component, or service and report findings to [Assignment: organization-defined personnel].",
	Section:       "System and Services Acquisition (SA)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var nist_4_sc_2 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_2",
	Name:          "Application Partitioning (SC-2)",
	Description:   "The information system separates user functionality (including user interface services) from information system management functionality.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges"},
}
var nist_4_sc_4 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_4",
	Name:          "Information In Shared Resources (SC-4)",
	Description:   "The information system prevents unauthorized and unintended information transfer via shared system resources.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{},
}
var nist_4_sc_5 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_5",
	Name:          "Denial Of Service Protection (SC-5)",
	Description:   "The information system protects against or limits the effects of the following types of denial of service attacks: [Assignment: organization-defined types of denial of service attacks or references to sources for such information] by employing [Assignment: organization-defined security safeguards].",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"rds_instance_deletion_protection", "rds_instance_multi_az"},
}
var nist_4_sc_7_3 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_7_3",
	Name:          "SC-7(3) Access Points",
	Description:   "The organization limits the number of external network connections to the information system.",
	Section:       "System and Communications Protection (SC)",
	SubSection:    "Boundary Protection (SC-7)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var nist_4_sc_7 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_7",
	Name:          "Boundary Protection (SC-7)",
	Description:   "The information system: a. Monitors and controls communications at the external boundary of the system and at key internal boundaries within the system; b. Implements subnetworks for publicly accessible system components that are [Selection: physically; logically] separated from internal organizational networks; and c. Connects to external networks or information systems only through managed interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "elbv2_waf_acl_attached", "elb_ssl_listeners", "emr_cluster_master_nodes_no_public_ip", "opensearch_service_domains_node_to_node_encryption_enabled", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_secure_transport_policy", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var nist_4_sc_8_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_8_1",
	Name:          "SC-8(1) Cryptographic Or Alternate Physical Protection",
	Description:   "The information system implements cryptographic mechanisms to [Selection (one or more): prevent unauthorized disclosure of information; detect changes to information] during transmission unless otherwise protected by [Assignment: organization-defined alternative physical safeguards].",
	Section:       "System and Communications Protection (SC)",
	SubSection:    "Transmission Confidentiality And Integrity (SC-8)",
	Checks:        []string{"elb_ssl_listeners", "opensearch_service_domains_node_to_node_encryption_enabled", "s3_bucket_secure_transport_policy"},
}
var nist_4_sc_8 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_8",
	Name:          "Transmission Confidentiality And Integrity (SC-8)",
	Description:   "The information system protects the [Selection (one or more): confidentiality; integrity] of transmitted information.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"elb_ssl_listeners", "opensearch_service_domains_node_to_node_encryption_enabled", "s3_bucket_secure_transport_policy"},
}
var nist_4_sc_12 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_12",
	Name:          "Cryptographic Key Establishment And Management (SC-12)",
	Description:   "The organization establishes and manages cryptographic keys for required cryptography employed within the information system in accordance with [Assignment: organization-defined requirements for key generation, distribution, storage, access, and destruction].",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"acm_certificates_expiration_check", "kms_cmk_rotation_enabled"},
}
var nist_4_sc_13 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_13",
	Name:          "Cryptographic Protection (SC-13)",
	Description:   "The information system implements [Assignment: organization-defined cryptographic uses and type of cryptography required for each use] in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"dynamodb_tables_kms_cmk_encryption_enabled"},
}
var nist_4_sc_23 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_23",
	Name:          "Session Authenticity (SC-23)",
	Description:   "The information system protects the authenticity of communications sessions.",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{},
}
var nist_4_sc_28 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "sc_28",
	Name:          "Protection Of Information At Rest (SC-28)",
	Description:   "The information system protects the [Selection (one or more): confidentiality; integrity] of [Assignment: organization-defined information at rest].",
	Section:       "System and Communications Protection (SC)",
	Checks:        []string{"cloudtrail_kms_encryption_enabled", "ec2_ebs_volume_encryption", "ec2_ebs_default_encryption", "efs_encryption_at_rest_enabled", "opensearch_service_domains_encryption_at_rest_enabled", "cloudwatch_log_group_kms_encryption_enabled", "rds_instance_storage_encrypted", "rds_instance_storage_encrypted", "redshift_cluster_audit_logging", "s3_bucket_default_encryption", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled"},
}
var nist_4_si_2_2 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "si_2_2",
	Name:          "SI-2(2) Automates Flaw Remediation Status",
	Description:   "The organization employs automated mechanisms to determine the state of information system components with regard to flaw remediation.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Flaw Remediation (SI-2)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching", "ssm_managed_compliant_patching"},
}
var nist_4_si_4_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "si_4_1",
	Name:          "SI-4(1) System-Wide Intrusion Detection System",
	Description:   "The organization connects and configures individual intrusion detection tools into an information system-wide intrusion detection system.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"guardduty_is_enabled"},
}
var nist_4_si_4_2 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "si_4_2",
	Name:          "SI-4(2) Automated Tools For Real-Time Analysis",
	Description:   "The organization employs automated tools to support near real-time analysis of events.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "guardduty_is_enabled", "securityhub_enabled"},
}
var nist_4_si_4_4 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "si_4_4",
	Name:          "SI-4(4) Inbound and Outbound Communications Traffic",
	Description:   "The information system monitors inbound and outbound communications traffic continuously for unusual or unauthorized activities or conditions.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "guardduty_is_enabled", "securityhub_enabled"},
}
var nist_4_si_4_5 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "si_4_5",
	Name:          "SI-4(5) System-Generated Alerts",
	Description:   "The information system alerts organization-defined personnel or roles when the following indications of compromise or potential compromise occur: [Assignment: organization-defined compromise indicators].",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "guardduty_is_enabled", "securityhub_enabled"},
}
var nist_4_si_4_16 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "si_4_16",
	Name:          "SI-4(16) Correlate Monitoring Information",
	Description:   "The organization correlates information from monitoring tools employed throughout the information system.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Information System Monitoring (SI-4)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var nist_4_si_4 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "si_4",
	Name:          "Information System Monitoring (SI-4)",
	Description:   "The organization: a.Monitors the information system to detect: 1. Attacks and indicators of potential attacks in accordance with [Assignment: organization-defined monitoring objectives]; and 2.Unauthorized local, network, and remote connections; b. Identifies unauthorized use of the information system through [Assignment: organization-defined techniques and methods]; c. Deploys monitoring devices: 1. Strategically within the information system to collect organization-determined essential information; and 2. At ad hoc locations within the system to track specific types of transactions of interest to the organization; d. Protects information obtained from intrusion-monitoring tools from unauthorized access, modification, and deletion; e. Heightens the level of information system monitoring activity whenever there is an indication of increased risk to organizational operations and assets, individuals, other organizations, or the Nation based on law enforcement information, intelligence information, or other credible sources of information; f. Obtains legal opinion with regard to information system monitoring activities in accordance with applicable federal laws, Executive Orders, directives, policies, or regulations; and g. Provides [Assignment: organization-defined information system monitoring information] to [Assignment: organization-defined personnel or roles] [Selection (one or more): as needed; [Assignment: organization-defined frequency]].",
	Section:       "System and Information Integrity (SI)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "elbv2_waf_acl_attached", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var nist_4_si_7_1 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "si_7_1",
	Name:          "SI-7(1) Integrity Checks",
	Description:   "The information system performs an integrity check of security relevant events at least monthly.",
	Section:       "System and Information Integrity (SI)",
	SubSection:    "Software, Firmware, and Information Integrity (SI-7)",
	Checks:        []string{"cloudtrail_log_file_validation_enabled", "ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching"},
}
var nist_4_si_7 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "si_7",
	Name:          "Software, Firmware, and Information Integrity (SI-7)",
	Description:   "The organization employs integrity verification tools to detect unauthorized changes to [Assignment: organization-defined software, firmware, and information].",
	Section:       "System and Information Integrity (SI)",
	Checks:        []string{"cloudtrail_log_file_validation_enabled"},
}
var nist_4_si_12 = &NistComp{
	Framework:     "NIST-800-53-Revision-4",
	Provider:      "AWS",
	Frameworkdesc: "NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.",
	Id:            "si_12",
	Name:          "Information Handling and Retention (SI-12)",
	Description:   "The organization handles and retains information within the information system and information output from the system in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and operational requirements.",
	Section:       "System and Information Integrity (SI)",
	Checks:        []string{"cloudwatch_log_group_retention_policy_specific_days_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "s3_bucket_object_versioning"},
}
