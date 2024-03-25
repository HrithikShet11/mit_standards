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

var Nist_csf_ae_1 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ae_1",
	Name:          "DE.AE-1",
	Description:   "A baseline of network operations and expected data flows for users and systems is established and managed.",
	Section:       "Detect (DE)",
	SubSection:    "Anomalies and Events (DE.AE)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "ec2_securitygroup_default_restrict_traffic", "vpc_flow_logs_enabled", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_csf_ae_2 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ae_2",
	Name:          "DE.AE-2",
	Description:   "Detected events are analyzed to understand attack targets and methods.",
	Section:       "Detect (DE)",
	SubSection:    "Anomalies and Events (DE.AE)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var Nist_csf_ae_3 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ae_3",
	Name:          "DE.AE-3",
	Description:   "Event data are collected and correlated from multiple sources and sensors.",
	Section:       "Detect (DE)",
	SubSection:    "Anomalies and Events (DE.AE)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var Nist_csf_ae_4 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ae_4",
	Name:          "DE.AE-4",
	Description:   "Impact of events is determined.",
	Section:       "Detect (DE)",
	SubSection:    "Anomalies and Events (DE.AE)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "s3_bucket_server_access_logging_enabled", "securityhub_enabled"},
}
var Nist_csf_ae_5 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ae_5",
	Name:          "DE.AE-5",
	Description:   "Incident alert thresholds are established.",
	Section:       "Detect (DE)",
	SubSection:    "Anomalies and Events (DE.AE)",
	Checks:        []string{"cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured"},
}
var Nist_csf_cm_1 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "cm_1",
	Name:          "DE.CM-1",
	Description:   "The network is monitored to detect potential cybersecurity events.",
	Section:       "Detect (DE)",
	SubSection:    "Security Continuous Monitoring (DE.CM)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "guardduty_is_enabled", "s3_bucket_server_access_logging_enabled", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
var Nist_csf_cm_2 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "cm_2",
	Name:          "DE.CM-2",
	Description:   "The physical environment is monitored to detect potential cybersecurity events.",
	Section:       "Detect (DE)",
	SubSection:    "Security Continuous Monitoring (DE.CM)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "config_recorder_all_regions_enabled", "ec2_instance_imdsv2_enabled", "guardduty_is_enabled", "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes", "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled", "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled", "cloudwatch_log_metric_filter_authentication_failures", "cloudwatch_log_metric_filter_sign_in_without_mfa", "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk", "cloudwatch_log_metric_filter_policy_changes", "cloudwatch_log_metric_filter_root_usage", "cloudwatch_log_metric_filter_security_group_changes", "cloudwatch_log_metric_filter_unauthorized_api_calls", "rds_instance_enhanced_monitoring_enabled", "securityhub_enabled"},
}
var Nist_csf_cm_3 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "cm_3",
	Name:          "DE.CM-3",
	Description:   "Personnel activity is monitored to detect potential cybersecurity events.",
	Section:       "Detect (DE)",
	SubSection:    "Security Continuous Monitoring (DE.CM)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "guardduty_is_enabled", "s3_bucket_server_access_logging_enabled", "securityhub_enabled"},
}
var Nist_csf_cm_4 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "cm_4",
	Name:          "DE.CM-4",
	Description:   "Malicious code is detected.",
	Section:       "Detect (DE)",
	SubSection:    "Security Continuous Monitoring (DE.CM)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var Nist_csf_cm_5 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "cm_5",
	Name:          "DE.CM-5",
	Description:   "Unauthorized mobile code is detected.",
	Section:       "Detect (DE)",
	SubSection:    "Security Continuous Monitoring (DE.CM)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "elbv2_waf_acl_attached", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var Nist_csf_cm_6 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "cm_6",
	Name:          "DE.CM-6",
	Description:   "External service provider activity is monitored to detect potential cybersecurity events.",
	Section:       "Detect (DE)",
	SubSection:    "Security Continuous Monitoring (DE.CM)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "guardduty_is_enabled", "s3_bucket_server_access_logging_enabled", "securityhub_enabled"},
}
var Nist_csf_cm_7 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "cm_7",
	Name:          "DE.CM-7",
	Description:   "Monitoring for unauthorized personnel, connections, devices, and software is performed.",
	Section:       "Detect (DE)",
	SubSection:    "Security Continuous Monitoring (DE.CM)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "guardduty_is_enabled", "s3_bucket_server_access_logging_enabled", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
var Nist_csf_cp_4 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "cp_4",
	Name:          "DE.DP-4",
	Description:   "Event detection information is communicated.",
	Section:       "Detect (DE)",
	SubSection:    "Detection Processes (DE.DP)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "elbv2_waf_acl_attached", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var Nist_csf_cp_5 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "cp_5",
	Name:          "DE.DP-5",
	Description:   "Detection processes are continuously improved.",
	Section:       "Detect (DE)",
	SubSection:    "Detection Processes (DE.DP)",
	Checks:        []string{"ec2_instance_imdsv2_enabled"},
}
var Nist_csf_am_1 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "am_1",
	Name:          "ID.AM-1",
	Description:   "Physical devices and systems within the organization are inventoried.",
	Section:       "Identify (ID)",
	SubSection:    "Asset Management (ID.AM)",
	Checks:        []string{"config_recorder_all_regions_enabled", "ec2_instance_managed_by_ssm"},
}
var Nist_csf_am_2 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "am_2",
	Name:          "ID.AM-2",
	Description:   "Software platforms and applications within the organization are inventoried.",
	Section:       "Identify (ID)",
	SubSection:    "Asset Management (ID.AM)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching"},
}
var Nist_csf_am_3 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "am_3",
	Name:          "ID.AM-3",
	Description:   "Organizational communication and data flows are mapped.",
	Section:       "Identify (ID)",
	SubSection:    "Asset Management (ID.AM)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_multi_region_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var Nist_csf_am_5 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "am_5",
	Name:          "ID.AM-5",
	Description:   "Resources (e.g., hardware, devices, data, time, personnel, and software) are prioritized based on their classification, criticality, and business value.",
	Section:       "Identify (ID)",
	SubSection:    "Asset Management (ID.AM)",
	Checks:        []string{},
}
var Nist_csf_am_6 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "am_6",
	Name:          "ID.AM-6",
	Description:   "Cybersecurity roles and responsibilities for the entire workforce and third-party stakeholders (e.g., suppliers, customers, partners) are established.",
	Section:       "Identify (ID)",
	SubSection:    "Asset Management (ID.AM)",
	Checks:        []string{},
}
var Nist_csf_be_5 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "be_5",
	Name:          "ID.BE-5",
	Description:   "Resilience requirements to support delivery of critical services are established for all operating states (e.g. under duress/attack, during recovery, normal operations)",
	Section:       "Identify (ID)",
	SubSection:    "Business Environment (ID.BE)",
	Checks:        []string{"elbv2_deletion_protection", "rds_instance_backup_enabled", "rds_instance_multi_az", "s3_bucket_object_versioning"},
}
var Nist_csf_ra_1 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ra_1",
	Name:          "ID.RA-1",
	Description:   "Asset vulnerabilities are identified and documented.",
	Section:       "Identify (ID)",
	SubSection:    "Risk Assessment (ID.RA)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled", "ssm_managed_compliant_patching"},
}
var Nist_csf_ra_2 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ra_2",
	Name:          "ID.RA-2",
	Description:   "Cyber threat intelligence is received from information sharing forums and sources.",
	Section:       "Identify (ID)",
	SubSection:    "Risk Assessment (ID.RA)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var Nist_csf_ra_3 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ra_3",
	Name:          "ID.RA-3",
	Description:   "Threats, both internal and external, are identified and documented.",
	Section:       "Identify (ID)",
	SubSection:    "Risk Assessment (ID.RA)",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var Nist_csf_ra_5 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ra_5",
	Name:          "ID.RA-5",
	Description:   "Threats, vulnerabilities, likelihoods, and impacts are used to determine risk.",
	Section:       "Identify (ID)",
	SubSection:    "Risk Assessment (ID.RA)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "config_recorder_all_regions_enabled", "ec2_instance_imdsv2_enabled", "guardduty_is_enabled", "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes", "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled", "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled", "cloudwatch_log_metric_filter_authentication_failures", "cloudwatch_log_metric_filter_sign_in_without_mfa", "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk", "cloudwatch_log_metric_filter_policy_changes", "cloudwatch_log_metric_filter_root_usage", "cloudwatch_log_metric_filter_security_group_changes", "cloudwatch_log_metric_filter_unauthorized_api_calls", "rds_instance_enhanced_monitoring_enabled", "securityhub_enabled"},
}
var Nist_csf_sc_4 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "sc_4",
	Name:          "ID.SC-4",
	Description:   "Suppliers and third-party partners are routinely assessed using audits, test results, or other forms of evaluations to confirm they are meeting their contractual obligations.",
	Section:       "Identify (ID)",
	SubSection:    "Supply Chain Risk Management (ID.SC)",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "config_recorder_all_regions_enabled", "ec2_instance_imdsv2_enabled", "guardduty_is_enabled", "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes", "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled", "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled", "cloudwatch_log_metric_filter_authentication_failures", "cloudwatch_log_metric_filter_sign_in_without_mfa", "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk", "cloudwatch_log_metric_filter_policy_changes", "cloudwatch_log_metric_filter_root_usage", "cloudwatch_log_metric_filter_security_group_changes", "cloudwatch_log_metric_filter_unauthorized_api_calls", "rds_instance_enhanced_monitoring_enabled", "securityhub_enabled"},
}
var Nist_csf_ac_1 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ac_1",
	Name:          "PR.AC-1",
	Description:   "Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes.",
	Section:       "Protect (PR)",
	SubSection:    "Identity Management and Access Control (PR.AC)",
	Checks:        []string{"iam_password_policy_reuse_24", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "iam_rotate_access_key_90_days", "iam_user_accesskey_unused", "iam_user_console_access_unused", "secretsmanager_automatic_rotation_enabled"},
}
var Nist_csf_ac_3 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ac_3",
	Name:          "PR.AC-3",
	Description:   "Remote access is managed.",
	Section:       "Protect (PR)",
	SubSection:    "Identity Management and Access Control (PR.AC)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "emr_cluster_master_nodes_no_public_ip", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_csf_ac_4 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ac_4",
	Name:          "PR.AC-4",
	Description:   "Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties.",
	Section:       "Protect (PR)",
	SubSection:    "Identity Management and Access Control (PR.AC)",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var Nist_csf_ac_5 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ac_5",
	Name:          "PR.AC-5",
	Description:   "Network integrity is protected (e.g., network segregation, network segmentation).",
	Section:       "Protect (PR)",
	SubSection:    "Identity Management and Access Control (PR.AC)",
	Checks:        []string{"acm_certificates_expiration_check", "ec2_ebs_public_snapshot", "ec2_instance_public_ip", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_csf_ac_6 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ac_6",
	Name:          "PR.AC-6",
	Description:   "Identities are proofed and bound to credentials and asserted in interactions.",
	Section:       "Protect (PR)",
	SubSection:    "Identity Management and Access Control (PR.AC)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_multi_region_enabled", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled"},
}
var Nist_csf_ac_7 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ac_7",
	Name:          "PR.AC-7",
	Description:   "Users, devices, and other assets are authenticated (e.g., single-factor, multi-factor) commensurate with the risk of the transaction (e.g., individuals’ security and privacy risks and other organizational risks).",
	Section:       "Protect (PR)",
	SubSection:    "Identity Management and Access Control (PR.AC)",
	Checks:        []string{"iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access"},
}
var Nist_csf_ds_1 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ds_1",
	Name:          "PR.DS-1",
	Description:   "Data-at-rest is protected.",
	Section:       "Protect (PR)",
	SubSection:    "Data Security (PR.DS)",
	Checks:        []string{"cloudtrail_kms_encryption_enabled", "ec2_ebs_volume_encryption", "efs_encryption_at_rest_enabled", "opensearch_service_domains_encryption_at_rest_enabled", "cloudwatch_log_group_kms_encryption_enabled", "rds_instance_storage_encrypted", "s3_bucket_default_encryption", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled"},
}
var Nist_csf_ds_2 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ds_2",
	Name:          "PR.DS-2",
	Description:   "Data-in-transit is protected.",
	Section:       "Protect (PR)",
	SubSection:    "Data Security (PR.DS)",
	Checks:        []string{"acm_certificates_expiration_check", "elb_ssl_listeners", "opensearch_service_domains_node_to_node_encryption_enabled", "s3_bucket_secure_transport_policy"},
}
var Nist_csf_ds_3 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ds_3",
	Name:          "PR.DS-3",
	Description:   "Assets are formally managed throughout removal, transfers, and disposition.",
	Section:       "Protect (PR)",
	SubSection:    "Data Security (PR.DS)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching", "ec2_elastic_ip_unassigned"},
}
var Nist_csf_ds_4 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ds_4",
	Name:          "PR.DS-4",
	Description:   "Adequate capacity to ensure availability is maintained.",
	Section:       "Protect (PR)",
	SubSection:    "Data Security (PR.DS)",
	Checks:        []string{"elbv2_deletion_protection", "rds_instance_enhanced_monitoring_enabled", "rds_instance_backup_enabled", "rds_instance_multi_az", "s3_bucket_object_versioning"},
}
var Nist_csf_ds_5 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ds_5",
	Name:          "PR.DS-5",
	Description:   "Protections against data leaks are implemented.",
	Section:       "Protect (PR)",
	SubSection:    "Data Security (PR.DS)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "ec2_ebs_public_snapshot", "elbv2_logging_enabled", "elb_logging_enabled", "guardduty_is_enabled", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_server_access_logging_enabled", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
var Nist_csf_ds_6 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ds_6",
	Name:          "PR.DS-6",
	Description:   "Integrity checking mechanisms are used to verify software, firmware, and information integrity.",
	Section:       "Protect (PR)",
	SubSection:    "Data Security (PR.DS)",
	Checks:        []string{"cloudtrail_log_file_validation_enabled"},
}
var Nist_csf_ds_7 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ds_7",
	Name:          "PR.DS-7",
	Description:   "The development and testing environment(s) are separate from the production environment.",
	Section:       "Protect (PR)",
	SubSection:    "Data Security (PR.DS)",
	Checks:        []string{"cloudtrail_log_file_validation_enabled", "ec2_instance_managed_by_ssm", "ec2_instance_older_than_specific_days", "elbv2_deletion_protection", "ssm_managed_compliant_patching", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"},
}
var Nist_csf_ds_8 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ds_8",
	Name:          "PR.DS-8",
	Description:   "Integrity checking mechanisms are used to verify hardware integrity.",
	Section:       "Protect (PR)",
	SubSection:    "Data Security (PR.DS)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "securityhub_enabled"},
}
var Nist_csf_ip_1 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ip_1",
	Name:          "PR.IP-1",
	Description:   "A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles (e.g. concept of least functionality).",
	Section:       "Protect (PR)",
	SubSection:    "Information Protection Processes and Procedures (PR.IP)",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ec2_instance_older_than_specific_days", "ssm_managed_compliant_patching"},
}
var Nist_csf_ip_2 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ip_2",
	Name:          "PR.IP-2",
	Description:   "A System Development Life Cycle to manage systems is implemented.",
	Section:       "Protect (PR)",
	SubSection:    "Information Protection Processes and Procedures (PR.IP)",
	Checks:        []string{"ec2_instance_managed_by_ssm"},
}
var Nist_csf_ip_3 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ip_3",
	Name:          "PR.IP-3",
	Description:   "Configuration change control processes are in place.",
	Section:       "Protect (PR)",
	SubSection:    "Information Protection Processes and Procedures (PR.IP)",
	Checks:        []string{"elbv2_deletion_protection"},
}
var Nist_csf_ip_4 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ip_4",
	Name:          "PR.IP-4",
	Description:   "Backups of information are conducted, maintained, and tested periodically.",
	Section:       "Protect (PR)",
	SubSection:    "Information Protection Processes and Procedures (PR.IP)",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "rds_instance_backup_enabled", "s3_bucket_object_versioning"},
}
var Nist_csf_ip_7 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ip_7",
	Name:          "PR.IP-7",
	Description:   "Protection processes are improved.",
	Section:       "Protect (PR)",
	SubSection:    "Information Protection Processes and Procedures (PR.IP)",
	Checks:        []string{},
}
var Nist_csf_ip_8 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ip_8",
	Name:          "PR.IP-8",
	Description:   "Effectiveness of protection technologies is shared.",
	Section:       "Protect (PR)",
	SubSection:    "Information Protection Processes and Procedures (PR.IP)",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "eks_endpoints_not_publicly_accessible", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured"},
}
var Nist_csf_ip_9 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ip_9",
	Name:          "PR.IP-9",
	Description:   "Response plans (Incident Response and Business Continuity) and recovery plans (Incident Recovery and Disaster Recovery) are in place and managed.",
	Section:       "Protect (PR)",
	SubSection:    "Information Protection Processes and Procedures (PR.IP)",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "efs_have_backup_enabled", "elbv2_deletion_protection", "rds_instance_backup_enabled", "rds_instance_multi_az", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
var Nist_csf_ip_12 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ip_12",
	Name:          "PR.IP-12",
	Description:   "A vulnerability management plan is developed and implemented.",
	Section:       "Protect (PR)",
	SubSection:    "Information Protection Processes and Procedures (PR.IP)",
	Checks:        []string{"config_recorder_all_regions_enabled", "ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching", "ssm_managed_compliant_patching"},
}
var Nist_csf_ma_2 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "ma_2",
	Name:          "PR.MA-2",
	Description:   "Remote maintenance of organizational assets is approved, logged, and performed in a manner that prevents unauthorized access.",
	Section:       "Protect (PR)",
	SubSection:    "Maintenance (PR.MA)",
	Checks:        []string{"cloudtrail_multi_region_enabled", "cloudtrail_multi_region_enabled"},
}
var Nist_csf_pt_1 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "pt_1",
	Name:          "PR.PT-1",
	Description:   "Audit/log records are determined, documented, implemented, and reviewed in accordance with policy.",
	Section:       "Protect (PR)",
	SubSection:    "Protective Technology (PR.PT)",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var Nist_csf_pt_3 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "pt_3",
	Name:          "PR.PT-3",
	Description:   "The principle of least functionality is incorporated by configuring systems to provide only essential capabilities.",
	Section:       "Protect (PR)",
	SubSection:    "Protective Technology (PR.PT)",
	Checks:        []string{"ec2_ebs_public_snapshot", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "awslambda_function_url_public", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks"},
}
var Nist_csf_pt_4 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "pt_4",
	Name:          "PR.PT-4",
	Description:   "Communications and control networks are protected.",
	Section:       "Protect (PR)",
	SubSection:    "Protective Technology (PR.PT)",
	Checks:        []string{"awslambda_function_not_publicly_accessible", "rds_instance_no_public_access", "redshift_cluster_public_access", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_csf_pt_5 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "pt_5",
	Name:          "PR.PT-5",
	Description:   "Mechanisms (e.g., failsafe, load balancing, hot swap) are implemented to achieve resilience requirements in normal and adverse situations.",
	Section:       "Protect (PR)",
	SubSection:    "Protective Technology (PR.PT)",
	Checks:        []string{"elbv2_deletion_protection", "rds_instance_backup_enabled", "rds_instance_multi_az", "s3_bucket_object_versioning"},
}
var Nist_csf_rc_rp_1 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "rp_1",
	Name:          "RC.RP-1",
	Description:   "Recovery plan is executed during or after a cybersecurity incident.",
	Section:       "Recover (RC)",
	SubSection:    "Recovery Planning (RC.RP)",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "efs_have_backup_enabled", "elbv2_deletion_protection", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "rds_instance_multi_az", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
var Nist_csf_an_2 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "an_2",
	Name:          "RS.AN-2",
	Description:   "The impact of the incident is understood.",
	Section:       "Respond (RS)",
	SubSection:    "Analysis (RS.AN)",
	Checks:        []string{"guardduty_no_high_severity_findings"},
}
var Nist_csf_mi_3 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "mi_3",
	Name:          "RS.MI-3",
	Description:   "Newly identified vulnerabilities are mitigated or documented as accepted risks.",
	Section:       "Respond (RS)",
	SubSection:    "Mitigation (RS.MI)",
	Checks:        []string{"guardduty_no_high_severity_findings"},
}
var Nist_csf_rs_rp_1 = &NistComp{
	Framework:     "NIST-CSF",
	Provider:      "AWS",
	Frameworkdesc: "The NIST Cybersecurity Framework (CSF) is supported by governments and industries worldwide as a recommended baseline for use by any organization, regardless of sector or size. The NIST Cybersecurity Framework consists of three primary components: the framework core, the profiles, and the implementation tiers. The framework core contains desired cybersecurity activities and outcomes organized into 23 categories that cover the breadth of cybersecurity objectives for an organization. The profiles contain an organization's unique alignment of their organizational requirements and objectives, risk appetite, and resources using the desired outcomes of the framework core. The implementation tiers describe the degree to which an organization’s cybersecurity risk management practices exhibit the characteristics defined in the framework core.",
	Id:            "rp_1",
	Name:          "RS.RP-1",
	Description:   "Response plan is executed during or after an incident.",
	Section:       "Respond (RS)",
	SubSection:    "Response Planning (RS.RP)",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "efs_have_backup_enabled", "elbv2_deletion_protection", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "rds_instance_multi_az", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
