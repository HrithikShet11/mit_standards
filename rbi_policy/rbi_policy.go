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

var Rbi_annex_i_1_1 = &NistComp{
	Framework:     "RBI-Cyber-Security-Framework",
	Provider:      "AWS",
	Frameworkdesc: "The Reserve Bank had prescribed a set of baseline cyber security controls for primary (Urban) cooperative banks (UCBs) in October 2018. On further examination, it has been decided to prescribe a comprehensive cyber security framework for the UCBs, as a graded approach, based on their digital depth and interconnectedness with the payment systems landscape, digital products offered by them and assessment of cyber security risk. The framework would mandate implementation of progressively stronger security measures based on the nature, variety and scale of digital product offerings of banks.",
	Id:            "annex_i_1_1",
	Name:          "Annex I (1.1)",
	Description:   "UCBs should maintain an up-to-date business IT Asset Inventory Register containing the following fields, as a minimum: a) Details of the IT Asset (viz., hardware/software/network devices, key personnel, services, etc.), b. Details of systems where customer data are stored, c. Associated business applications, if any, d. Criticality of the IT asset (For example, High/Medium/Low).",
	ItemId:        "annex_i_1_1",
	Service:       "ec2",
	Checks:        []string{"ec2_instance_managed_by_ssm"},
}
var Rbi_annex_i_1_3 = &NistComp{
	Framework:     "RBI-Cyber-Security-Framework",
	Provider:      "AWS",
	Frameworkdesc: "The Reserve Bank had prescribed a set of baseline cyber security controls for primary (Urban) cooperative banks (UCBs) in October 2018. On further examination, it has been decided to prescribe a comprehensive cyber security framework for the UCBs, as a graded approach, based on their digital depth and interconnectedness with the payment systems landscape, digital products offered by them and assessment of cyber security risk. The framework would mandate implementation of progressively stronger security measures based on the nature, variety and scale of digital product offerings of banks.",
	Id:            "annex_i_1_3",
	Name:          "Annex I (1.3)",
	Description:   "Appropriately manage and provide protection within and outside UCB/network, keeping in mind how the data/information is stored, transmitted, processed, accessed and put to use within/outside the UCB’s network, and level of risk they are exposed to depending on the sensitivity of the data/information.",
	ItemId:        "annex_i_1_3",
	Service:       "aws",
	Checks:        []string{"acm_certificates_expiration_check", "apigateway_restapi_client_certificate_enabled", "cloudtrail_kms_encryption_enabled", "dynamodb_tables_kms_cmk_encryption_enabled", "ec2_ebs_volume_encryption", "ec2_ebs_public_snapshot", "ec2_ebs_volume_encryption", "ec2_instance_public_ip", "efs_encryption_at_rest_enabled", "elbv2_insecure_ssl_ciphers", "elb_ssl_listeners", "emr_cluster_master_nodes_no_public_ip", "opensearch_service_domains_encryption_at_rest_enabled", "opensearch_service_domains_node_to_node_encryption_enabled", "kms_cmk_rotation_enabled", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "cloudwatch_log_group_kms_encryption_enabled", "rds_instance_storage_encrypted", "rds_instance_no_public_access", "rds_instance_storage_encrypted", "rds_snapshots_public_access", "redshift_cluster_audit_logging", "redshift_cluster_public_access", "s3_bucket_default_encryption", "s3_bucket_default_encryption", "s3_bucket_secure_transport_policy", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_bucket_public_access", "sagemaker_notebook_instance_without_direct_internet_access_configured", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled", "ec2_networkacl_allow_ingress_any_port"},
}
var Rbi_annex_i_5_1 = &NistComp{
	Framework:     "RBI-Cyber-Security-Framework",
	Provider:      "AWS",
	Frameworkdesc: "The Reserve Bank had prescribed a set of baseline cyber security controls for primary (Urban) cooperative banks (UCBs) in October 2018. On further examination, it has been decided to prescribe a comprehensive cyber security framework for the UCBs, as a graded approach, based on their digital depth and interconnectedness with the payment systems landscape, digital products offered by them and assessment of cyber security risk. The framework would mandate implementation of progressively stronger security measures based on the nature, variety and scale of digital product offerings of banks.",
	Id:            "annex_i_5_1",
	Name:          "Annex I (5.1)",
	Description:   "The firewall configurations should be set to the highest security level and evaluation of critical device (such as firewall, network switches, security devices, etc.) configurations should be done periodically.",
	ItemId:        "annex_i_5_1",
	Service:       "aws",
	Checks:        []string{"apigateway_restapi_waf_acl_attached", "elbv2_waf_acl_attached", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Rbi_annex_i_6 = &NistComp{
	Framework:     "RBI-Cyber-Security-Framework",
	Provider:      "AWS",
	Frameworkdesc: "The Reserve Bank had prescribed a set of baseline cyber security controls for primary (Urban) cooperative banks (UCBs) in October 2018. On further examination, it has been decided to prescribe a comprehensive cyber security framework for the UCBs, as a graded approach, based on their digital depth and interconnectedness with the payment systems landscape, digital products offered by them and assessment of cyber security risk. The framework would mandate implementation of progressively stronger security measures based on the nature, variety and scale of digital product offerings of banks.",
	Id:            "annex_i_6",
	Name:          "Annex I (6)",
	Description:   "Put in place systems and processes to identify, track, manage and monitor the status of patches to servers, operating system and application software running at the systems used by the UCB officials (end-users). Implement and update antivirus protection for all servers and applicable end points preferably through a centralised system.",
	ItemId:        "annex_i_6",
	Service:       "aws",
	Checks:        []string{"guardduty_no_high_severity_findings", "rds_instance_minor_version_upgrade_enabled", "redshift_cluster_automatic_upgrades", "ssm_managed_compliant_patching", "ssm_managed_compliant_patching"},
}
var Rbi_annex_i_7_1 = &NistComp{
	Framework:     "RBI-Cyber-Security-Framework",
	Provider:      "AWS",
	Frameworkdesc: "The Reserve Bank had prescribed a set of baseline cyber security controls for primary (Urban) cooperative banks (UCBs) in October 2018. On further examination, it has been decided to prescribe a comprehensive cyber security framework for the UCBs, as a graded approach, based on their digital depth and interconnectedness with the payment systems landscape, digital products offered by them and assessment of cyber security risk. The framework would mandate implementation of progressively stronger security measures based on the nature, variety and scale of digital product offerings of banks.",
	Id:            "annex_i_7_1",
	Name:          "Annex I (7.1)",
	Description:   "Disallow administrative rights on end-user workstations/PCs/laptops and provide access rights on a ‘need to know’ and ‘need to do’ basis.",
	ItemId:        "annex_i_7_1",
	Service:       "iam",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_policy_attached_only_to_group_or_roles", "iam_no_root_access_key"},
}
var Rbi_annex_i_7_2 = &NistComp{
	Framework:     "RBI-Cyber-Security-Framework",
	Provider:      "AWS",
	Frameworkdesc: "The Reserve Bank had prescribed a set of baseline cyber security controls for primary (Urban) cooperative banks (UCBs) in October 2018. On further examination, it has been decided to prescribe a comprehensive cyber security framework for the UCBs, as a graded approach, based on their digital depth and interconnectedness with the payment systems landscape, digital products offered by them and assessment of cyber security risk. The framework would mandate implementation of progressively stronger security measures based on the nature, variety and scale of digital product offerings of banks.",
	Id:            "annex_i_7_2",
	Name:          "Annex I (7.2)",
	Description:   "Passwords should be set as complex and lengthy and users should not use same passwords for all the applications/systems/devices.",
	ItemId:        "annex_i_7_2",
	Service:       "iam",
	Checks:        []string{"iam_password_policy_reuse_24"},
}
var Rbi_annex_i_7_3 = &NistComp{
	Framework:     "RBI-Cyber-Security-Framework",
	Provider:      "AWS",
	Frameworkdesc: "The Reserve Bank had prescribed a set of baseline cyber security controls for primary (Urban) cooperative banks (UCBs) in October 2018. On further examination, it has been decided to prescribe a comprehensive cyber security framework for the UCBs, as a graded approach, based on their digital depth and interconnectedness with the payment systems landscape, digital products offered by them and assessment of cyber security risk. The framework would mandate implementation of progressively stronger security measures based on the nature, variety and scale of digital product offerings of banks.",
	Id:            "annex_i_7_3",
	Name:          "Annex I (7.3)",
	Description:   "Remote Desktop Protocol (RDP) which allows others to access the computer remotely over a network or over the internet should be always disabled and should be enabled only with the approval of the authorised officer of the UCB. Logs for such remote access shall be enabled and monitored for suspicious activities.",
	ItemId:        "annex_i_7_3",
	Service:       "vpc",
	Checks:        []string{"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"},
}
var Rbi_annex_i_7_4 = &NistComp{
	Framework:     "RBI-Cyber-Security-Framework",
	Provider:      "AWS",
	Frameworkdesc: "The Reserve Bank had prescribed a set of baseline cyber security controls for primary (Urban) cooperative banks (UCBs) in October 2018. On further examination, it has been decided to prescribe a comprehensive cyber security framework for the UCBs, as a graded approach, based on their digital depth and interconnectedness with the payment systems landscape, digital products offered by them and assessment of cyber security risk. The framework would mandate implementation of progressively stronger security measures based on the nature, variety and scale of digital product offerings of banks.",
	Id:            "annex_i_7_4",
	Name:          "Annex I (7.4)",
	Description:   "Implement appropriate (e.g. centralised) systems and controls to allow, manage, log and monitor privileged/super user/administrative access to critical systems (servers/databases, applications, network devices etc.)",
	ItemId:        "annex_i_7_4",
	Service:       "aws",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "cloudwatch_log_group_retention_policy_specific_days_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "opensearch_service_domains_cloudwatch_logging_enabled", "rds_instance_integration_cloudwatch_logs", "redshift_cluster_audit_logging", "s3_bucket_server_access_logging_enabled", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
var Rbi_annex_i_12 = &NistComp{
	Framework:     "RBI-Cyber-Security-Framework",
	Provider:      "AWS",
	Frameworkdesc: "The Reserve Bank had prescribed a set of baseline cyber security controls for primary (Urban) cooperative banks (UCBs) in October 2018. On further examination, it has been decided to prescribe a comprehensive cyber security framework for the UCBs, as a graded approach, based on their digital depth and interconnectedness with the payment systems landscape, digital products offered by them and assessment of cyber security risk. The framework would mandate implementation of progressively stronger security measures based on the nature, variety and scale of digital product offerings of banks.",
	Id:            "annex_i_12",
	Name:          "Annex I (12)",
	Description:   "Take periodic back up of the important data and store this data ‘off line’ (i.e., transferring important files to a storage device that can be detached from a computer/system after copying all the files).",
	ItemId:        "annex_i_12",
	Service:       "aws",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
