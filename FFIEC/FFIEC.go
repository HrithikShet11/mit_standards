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

var FFIEC_d1_g_it_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d1-g-it-b-1",
	Name:          "D1.G.IT.B.1",
	Description:   "An inventory of organizational assets (e.g., hardware, software, data, and systems hosted externally) is maintained.",
	Section:       "Cyber Risk Management and Oversight (Domain 1)",
	SubSection:    "Governance (G)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ec2_instance_older_than_specific_days", "ec2_elastic_ip_unassigned"},
}
var FFIEC_d1_rm_ra_b_2 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d1-rm-ra-b-2",
	Name:          "D1.RM.RA.B.2",
	Description:   "The risk assessment identifies Internet- based systems and high-risk transactions that warrant additional authentication controls.",
	Section:       "Cyber Risk Management and Oversight (Domain 1)",
	SubSection:    "Risk Management (RM)",
	Checks:        []string{"guardduty_is_enabled"},
}
var FFIEC_d1_rm_rm_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d1-rm-rm-b-1",
	Name:          "D1.RM.Rm.B.1",
	Description:   "An information security and business continuity risk management function(s) exists within the institution.",
	Section:       "Cyber Risk Management and Oversight (Domain 1)",
	SubSection:    "Risk Management (RM)",
	Checks:        []string{"rds_instance_backup_enabled", "rds_instance_backup_enabled", "rds_instance_multi_az", "redshift_cluster_automated_snapshot"},
}
var FFIEC_d2_is_is_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d2-is-is-b-1",
	Name:          "D2.IS.Is.B.1",
	Description:   "Information security threats are gathered and shared with applicable internal employees.",
	Section:       "Threat Intelligence and Collaboration (Domain 2)",
	SubSection:    "Information Sharing (IS)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "guardduty_is_enabled", "securityhub_enabled"},
}
var FFIEC_d2_ma_ma_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d2-ma-ma-b-1",
	Name:          "D2.MA.Ma.B.1",
	Description:   "Information security threats are gathered and shared with applicable internal employees.",
	Section:       "Threat Intelligence and Collaboration (Domain 2)",
	SubSection:    "Monitoring and Analyzing (MA)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "cloudwatch_log_group_retention_policy_specific_days_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "opensearch_service_domains_cloudwatch_logging_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var FFIEC_d2_ma_ma_b_2 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d2-ma-ma-b-2",
	Name:          "D2.MA.Ma.B.2",
	Description:   "Computer event logs are used for investigations once an event has occurred.",
	Section:       "Threat Intelligence and Collaboration (Domain 2)",
	SubSection:    "Monitoring and Analyzing (MA)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "opensearch_service_domains_cloudwatch_logging_enabled", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var FFIEC_d2_ti_ti_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d2-ti-ti-b-1",
	Name:          "D2.TI.Ti.B.1",
	Description:   "The institution belongs or subscribes to a threat and vulnerability information-sharing source(s) that provides information on threats (e.g., FS-ISAC, US- CERT).",
	Section:       "Threat Intelligence and Collaboration (Domain 2)",
	SubSection:    "Threat Intelligence (TI)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var FFIEC_d2_ti_ti_b_2 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d2-ti-ti-b-2",
	Name:          "D2.TI.Ti.B.2",
	Description:   "Threat information is used to monitor threats and vulnerabilities.",
	Section:       "Threat Intelligence and Collaboration (Domain 2)",
	SubSection:    "Threat Intelligence (TI)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled", "ssm_managed_compliant_patching"},
}
var FFIEC_d2_ti_ti_b_3 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d2-ti-ti-b-3",
	Name:          "D2.TI.Ti.B.3",
	Description:   "Threat information is used to enhance internal risk management and controls.",
	Section:       "Threat Intelligence and Collaboration (Domain 2)",
	SubSection:    "Threat Intelligence (TI)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var FFIEC_d3_cc_pm_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-cc-pm-b-1",
	Name:          "D3.CC.PM.B.1",
	Description:   "A patch management program is implemented and ensures that software and firmware patches are applied in a timely manner.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Corrective Controls (CC)",
	Checks:        []string{"rds_instance_minor_version_upgrade_enabled", "redshift_cluster_automatic_upgrades", "ssm_managed_compliant_patching"},
}
var FFIEC_d3_cc_pm_b_3 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-cc-pm-b-3",
	Name:          "D3.CC.PM.B.3",
	Description:   "Patch management reports are reviewed and reflect missing security patches.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Corrective Controls (CC)",
	Checks:        []string{"rds_instance_minor_version_upgrade_enabled", "redshift_cluster_automatic_upgrades", "ssm_managed_compliant_patching"},
}
var FFIEC_d3_dc_an_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-dc-an-b-1",
	Name:          "D3.DC.An.B.1",
	Description:   "The institution is able to detect anomalous activities through monitoring across the environment.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Detective Controls (DC)",
	Checks:        []string{"guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var FFIEC_d3_dc_an_b_2 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-dc-an-b-2",
	Name:          "D3.DC.An.B.2",
	Description:   "Customer transactions generating anomalous activity alerts are monitored and reviewed.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Detective Controls (DC)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var FFIEC_d3_dc_an_b_3 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-dc-an-b-3",
	Name:          "D3.DC.An.B.3",
	Description:   "Logs of physical and/or logical access are reviewed following events.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Detective Controls (DC)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "opensearch_service_domains_cloudwatch_logging_enabled", "rds_instance_integration_cloudwatch_logs", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var FFIEC_d3_dc_an_b_4 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-dc-an-b-4",
	Name:          "D3.DC.An.B.4",
	Description:   "Access to critical systems by third parties is monitored for unauthorized or unusual activity.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Detective Controls (DC)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "opensearch_service_domains_cloudwatch_logging_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var FFIEC_d3_dc_an_b_5 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-dc-an-b-5",
	Name:          "D3.DC.An.B.5",
	Description:   "Elevated privileges are monitored.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Detective Controls (DC)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled"},
}
var FFIEC_d3_dc_ev_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-dc-ev-b-1",
	Name:          "D3.DC.Ev.B.1",
	Description:   "A normal network activity baseline is established.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Detective Controls (DC)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "redshift_cluster_audit_logging", "vpc_flow_logs_enabled"},
}
var FFIEC_d3_dc_ev_b_2 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-dc-ev-b-2",
	Name:          "D3.DC.Ev.B.2",
	Description:   "Mechanisms (e.g., antivirus alerts, log event alerts) are in place to alert management to potential attacks.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Detective Controls (DC)",
	Checks:        []string{"guardduty_is_enabled"},
}
var FFIEC_d3_dc_ev_b_3 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-dc-ev-b-3",
	Name:          "D3.DC.Ev.B.3",
	Description:   "Processes are in place to monitor for the presence of unauthorized users, devices, connections, and software.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Detective Controls (DC)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "guardduty_is_enabled", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
var FFIEC_d3_dc_th_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-dc-th-b-1",
	Name:          "D3.DC.Th.B.1",
	Description:   "Independent testing (including penetration testing and vulnerability scanning) is conducted according to the risk assessment for external-facing systems and the internal network.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Detective Controls (DC)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled", "ssm_managed_compliant_patching"},
}
var FFIEC_d3_pc_am_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-1",
	Name:          "D3.PC.Am.B.1",
	Description:   "Employee access is granted to systems and confidential data based on job responsibilities and the principles of least privilege.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"ec2_instance_profile_attached", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key"},
}
var FFIEC_d3_pc_am_b_10 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-10",
	Name:          "D3.PC.Am.B.10",
	Description:   "Production and non-production environments are segregated to prevent unauthorized access or changes to information assets. (*N/A if no production environment exists at the institution or the institution's third party.)",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FFIEC_d3_pc_am_b_12 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-12",
	Name:          "D3.PC.Am.B.12",
	Description:   "All passwords are encrypted in storage and in transit.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"apigateway_restapi_client_certificate_enabled", "ec2_ebs_volume_encryption", "ec2_ebs_default_encryption", "efs_encryption_at_rest_enabled", "opensearch_service_domains_encryption_at_rest_enabled", "opensearch_service_domains_node_to_node_encryption_enabled", "rds_instance_storage_encrypted", "redshift_cluster_audit_logging", "s3_bucket_default_encryption", "s3_bucket_secure_transport_policy"},
}
var FFIEC_d3_pc_am_b_13 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-13",
	Name:          "D3.PC.Am.B.13",
	Description:   "Confidential data is encrypted when transmitted across public or untrusted networks (e.g., Internet).",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"apigateway_restapi_client_certificate_enabled", "elbv2_insecure_ssl_ciphers", "elb_ssl_listeners", "s3_bucket_secure_transport_policy"},
}
var FFIEC_d3_pc_am_b_15 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-15",
	Name:          "D3.PC.Am.B.15",
	Description:   "Remote access to critical systems by employees, contractors, and third parties uses encrypted connections and multifactor authentication.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"apigateway_restapi_client_certificate_enabled", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "s3_bucket_secure_transport_policy"},
}
var FFIEC_d3_pc_am_b_16 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-16",
	Name:          "D3.PC.Am.B.16",
	Description:   "Administrative, physical, or technical controls are in place to prevent users without administrative responsibilities from installing unauthorized software.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges"},
}
var FFIEC_d3_pc_am_b_2 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-2",
	Name:          "D3.PC.Am.B.2",
	Description:   "Employee access to systems and confidential data provides for separation of duties.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges"},
}
var FFIEC_d3_pc_am_b_3 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-3",
	Name:          "D3.PC.Am.B.3",
	Description:   "Elevated privileges (e.g., administrator privileges) are limited and tightly controlled (e.g., assigned to individuals, not shared, and require stronger password controls",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_no_root_access_key"},
}
var FFIEC_d3_pc_am_b_6 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-6",
	Name:          "D3.PC.Am.B.6",
	Description:   "Identification and authentication are required and managed for access to systems, applications, and hardware.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"iam_password_policy_minimum_length_14", "iam_password_policy_lowercase", "iam_password_policy_number", "iam_password_policy_number", "iam_password_policy_symbol", "iam_password_policy_uppercase", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_rotate_access_key_90_days", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var FFIEC_d3_pc_am_b_7 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-7",
	Name:          "D3.PC.Am.B.7",
	Description:   "Access controls include password complexity and limits to password attempts and reuse.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"iam_password_policy_minimum_length_14", "iam_password_policy_lowercase", "iam_password_policy_number", "iam_password_policy_number", "iam_password_policy_symbol", "iam_password_policy_uppercase"},
}
var FFIEC_d3_pc_am_b_8 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-am-b-8",
	Name:          "D3.PC.Am.B.8",
	Description:   "All default passwords and unnecessary default accounts are changed before system implementation.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"iam_no_root_access_key"},
}
var FFIEC_d3_pc_im_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-im-b-1",
	Name:          "D3.PC.Im.B.1",
	Description:   "Network perimeter defense tools (e.g., border router and firewall) are used.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"acm_certificates_expiration_check", "apigateway_restapi_waf_acl_attached", "ec2_ebs_public_snapshot", "ec2_instance_public_ip", "elbv2_waf_acl_attached", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FFIEC_d3_pc_im_b_2 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-im-b-2",
	Name:          "D3.PC.Im.B.2",
	Description:   "Systems that are accessed from the Internet or by external parties are protected by firewalls or other similar devices.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"apigateway_restapi_waf_acl_attached", "elbv2_waf_acl_attached", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FFIEC_d3_pc_im_b_3 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-im-b-3",
	Name:          "D3.PC.Im.B.3",
	Description:   "All ports are monitored.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "vpc_flow_logs_enabled"},
}
var FFIEC_d3_pc_im_b_5 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-im-b-5",
	Name:          "D3.PC.Im.B.5",
	Description:   "Systems configurations (for servers, desktops, routers, etc.) follow industry standards and are enforced",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching", "ssm_managed_compliant_patching"},
}
var FFIEC_d3_pc_im_b_6 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-im-b-6",
	Name:          "D3.PC.Im.B.6",
	Description:   "Ports, functions, protocols and services are prohibited if no longer needed for business purposes.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FFIEC_d3_pc_im_b_7 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-im-b-7",
	Name:          "D3.PC.Im.B.7",
	Description:   "Access to make changes to systems configurations (including virtual machines and hypervisors) is controlled and monitored.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges"},
}
var FFIEC_d3_pc_se_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d3-pc-se-b-1",
	Name:          "D3.PC.Se.B.1",
	Description:   "Developers working for the institution follow secure program coding practices, as part of a system development life cycle (SDLC), that meet industry standards.",
	Section:       "Cybersecurity Controls (Domain 3)",
	SubSection:    "Preventative Controls (PC)",
	Checks:        []string{},
}
var FFIEC_d4_c_co_b_2 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d4-c-co-b-2",
	Name:          "D4.C.Co.B.2",
	Description:   "The institution ensures that third-party connections are authorized.",
	Section:       "External Dependency Management (Domain 4)",
	SubSection:    "Connections (C)",
	Checks:        []string{"ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var FFIEC_d5_dr_de_b_1 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d5-dr-de-b-1",
	Name:          "D5.DR.De.B.1",
	Description:   "Alert parameters are set for detecting information security incidents that prompt mitigating actions.",
	Section:       "Cyber Incident Management and Resilience (Domain 5)",
	SubSection:    "Detection, Response, & Mitigation (DR)",
	Checks:        []string{"cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "guardduty_is_enabled", "securityhub_enabled"},
}
var FFIEC_d5_dr_de_b_2 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d5-dr-de-b-2",
	Name:          "D5.DR.De.B.2",
	Description:   "System performance reports contain information that can be used as a risk indicator to detect information security incidents.",
	Section:       "Cyber Incident Management and Resilience (Domain 5)",
	SubSection:    "Detection, Response, & Mitigation (DR)",
	Checks:        []string{},
}
var FFIEC_d5_dr_de_b_3 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d5-dr-de-b-3",
	Name:          "D5.DR.De.B.3",
	Description:   "Tools and processes are in place to detect, alert, and trigger the incident response program.",
	Section:       "Cyber Incident Management and Resilience (Domain 5)",
	SubSection:    "Detection, Response, & Mitigation (DR)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "elbv2_logging_enabled", "elb_logging_enabled", "guardduty_is_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "securityhub_enabled"},
}
var FFIEC_d5_er_es_b_4 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d5-er-es-b-4",
	Name:          "D5.ER.Es.B.4",
	Description:   "Incidents are classified, logged and tracked.",
	Section:       "Cyber Incident Management and Resilience (Domain 5)",
	SubSection:    "Escalation and Reporting (ER)",
	Checks:        []string{"guardduty_no_high_severity_findings"},
}
var FFIEC_d5_ir_pl_b_6 = &NistComp{
	Framework:     "FFIEC",
	Provider:      "AWS",
	Frameworkdesc: "In light of the increasing volume and sophistication of cyber threats, the Federal Financial Institutions Examination Council (FFIEC) developed the Cybersecurity Assessment Tool (Assessment), on behalf of its members, to help institutions identify their risks and determine their cybersecurity maturity.",
	Id:            "d5-ir-pl-b-6",
	Name:          "D5.IR.Pl.B.6",
	Description:   "The institution plans to use business continuity, disaster recovery, and data backup programs to recover operations following an incident.",
	Section:       "Cyber Incident Management and Resilience (Domain 5)",
	SubSection:    "Incident Resilience Planning & Strategy (IR)",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "elbv2_deletion_protection", "rds_instance_enhanced_monitoring_enabled", "rds_instance_backup_enabled", "rds_instance_deletion_protection", "rds_instance_multi_az", "rds_instance_backup_enabled", "s3_bucket_object_versioning"},
}
