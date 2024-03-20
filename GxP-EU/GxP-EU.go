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

var GxP_EU_1_risk_management = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "1-risk-management",
	Name:          "1 Risk Management",
	Description:   "Risk management should be applied throughout the lifecycle of the computerised system taking into account patient safety, data integrity and product quality. As part of a risk management system, decisions on the extent of validation and data integrity controls should be based on a justified and documented risk assessment of the computerised system.",
	Section:       "General",
	Checks:        []string{"cloudtrail_multi_region_enabled", "securityhub_enabled"},
}
var GxP_EU_5_data = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "5-data",
	Name:          "5 Data",
	Description:   "Computerised systems exchanging data electronically with other systems should include appropriate built-in checks for the correct and secure entry and processing of data, in order to minimize the risks.",
	Section:       "Operational Phase",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
var GxP_EU_7_1_data_storage_damage_protection = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "7.1-data-storage-damage-protection",
	Name:          "7.1 Data Storage - Damage Protection",
	Description:   "Data should be secured by both physical and electronic means against damage. Stored data should be checked for accessibility, readability and accuracy. Access to data should be ensured throughout the retention period.",
	Section:       "Operational Phase",
	Checks:        []string{"cloudtrail_kms_encryption_enabled", "dynamodb_accelerator_cluster_encryption_enabled", "dynamodb_tables_kms_cmk_encryption_enabled", "dynamodb_tables_kms_cmk_encryption_enabled", "dynamodb_tables_pitr_enabled", "ec2_ebs_volume_encryption", "ec2_ebs_default_encryption", "efs_encryption_at_rest_enabled", "eks_cluster_kms_cmk_encryption_in_secrets_enabled", "opensearch_service_domains_encryption_at_rest_enabled", "cloudwatch_log_group_kms_encryption_enabled", "rds_instance_backup_enabled", "rds_instance_storage_encrypted", "rds_instance_backup_enabled", "rds_instance_storage_encrypted", "redshift_cluster_automated_snapshot", "redshift_cluster_audit_logging", "s3_bucket_default_encryption", "s3_bucket_default_encryption", "s3_bucket_object_versioning", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled"},
}
var GxP_EU_7_2_data_storage_backups = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "7.2-data-storage-backups",
	Name:          "7.2 Data Storage - Backups",
	Description:   "Regular back-ups of all relevant data should be done. Integrity and accuracy of backup data and the ability to restore the data should be checked during validation and monitored periodically.",
	Section:       "Operational Phase",
	Checks:        []string{"rds_instance_backup_enabled", "dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
var GxP_EU_8_2_printouts_data_changes = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "8.2-printouts-data-changes",
	Name:          "8.2 Printouts - Data Changes",
	Description:   "For records supporting batch release it should be possible to generate printouts indicating if any of the data has been changed since the original entry.",
	Section:       "Operational Phase",
	Checks:        []string{"cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled"},
}
var GxP_EU_9_audit_trails = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "9-audit-trails",
	Name:          "9 Audit Trails",
	Description:   "Consideration should be given, based on a risk assessment, to building into the system the creation of a record of all GMP-relevant changes and deletions (a system generated 'audit trail'). For change or deletion of GMP-relevant data the reason should be documented. Audit trails need to be available and convertible to a generally intelligible form and regularly reviewed.",
	Section:       "Operational Phase",
	Checks:        []string{"cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled"},
}
var GxP_EU_10_change_and_configuration_management = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "10-change-and-configuration-management",
	Name:          "10 Change and Configuration Management",
	Description:   "Any changes to a computerised system including system configurations should only be made in a controlled manner in accordance with a defined procedure.",
	Section:       "Operational Phase",
	Checks:        []string{"config_recorder_all_regions_enabled"},
}
var GxP_EU_12_4_security_audit_trail = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "12.4-security-audit-trail",
	Name:          "12.4 Security - Audit Trail",
	Description:   "Management systems for data and for documents should be designed to record the identity of operators entering, changing, confirming or deleting data including date and time.",
	Section:       "Operational Phase",
	Checks:        []string{"cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled"},
}
var GxP_EU_16_business_continuity = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "16-business-continuity",
	Name:          "16 Business Continuity",
	Description:   "For the availability of computerised systems supporting critical processes, provisions should be made to ensure continuity of support for those processes in the event of a system breakdown (e.g. a manual or alternative system). The time required to bring the alternative arrangements into use should be based on risk and appropriate for a particular system and the business process it supports. These arrangements should be adequately documented and tested.",
	Section:       "Operational Phase",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
var GxP_EU_17_archiving = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "17-archiving",
	Name:          "17 Archiving",
	Description:   "Data may be archived. This data should be checked for accessibility, readability and integrity. If relevant changes are to be made to the system (e.g. computer equipment or programs), then the ability to retrieve the data should be ensured and tested.",
	Section:       "Operational Phase",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
var GxP_EU_4_2_validation_documentation_change_control = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "4.2-validation-documentation-change-control",
	Name:          "4.2 Validation - Documentation Change Control",
	Description:   "Validation documentation should include change control records (if applicable) and reports on any deviations observed during the validation process.",
	Section:       "Project Phase",
	Checks:        []string{"cloudtrail_multi_region_enabled"},
}
var GxP_EU_4_5_validation_development_quality = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "4.5-validation-development-quality",
	Name:          "4.5 Validation - Development Quality",
	Description:   "The regulated user should take all reasonable steps, to ensure that the system has been developed in accordance with an appropriate quality management system. The supplier should be assessed appropriately.",
	Section:       "Project Phase",
	Checks:        []string{"config_recorder_all_regions_enabled"},
}
var GxP_EU_4_6_validation_quality_performance = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "4.6-validation-quality-performance",
	Name:          "4.6 Validation - Quality and Performance",
	Description:   "For the validation of bespoke or customised computerised systems there should be a process in place that ensures the formal assessment and reporting of quality and performance measures for all the life-cycle stages of the system.",
	Section:       "Project Phase",
	Checks:        []string{"config_recorder_all_regions_enabled"},
}
var GxP_EU_4_8_validation_data_transfer = &NistComp{
	Framework:     "GxP-EU-Annex-11",
	Provider:      "AWS",
	Frameworkdesc: "The GxP EU Annex 11 framework is the European equivalent to the FDA 21 CFR part 11 framework in the United States. This annex applies to all forms of computerized systems that are used as part of Good Manufacturing Practices (GMP) regulated activities. A computerized system is a set of software and hardware components that together fulfill certain functionalities. The application should be validated and IT infrastructure should be qualified. Where a computerized system replaces a manual operation, there should be no resultant decrease in product quality, process control, or quality assurance. There should be no increase in the overall risk of the process.",
	Id:            "4.8-validation-data-transfer",
	Name:          "4.8 Validation - Data Transfer",
	Description:   "If data are transferred to another data format or system, validation should include checks that data are not altered in value and/or meaning during this migration process.",
	Section:       "Project Phase",
	Checks:        []string{"dynamodb_tables_pitr_enabled", "dynamodb_tables_pitr_enabled", "efs_have_backup_enabled", "efs_have_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "rds_instance_backup_enabled", "redshift_cluster_automated_snapshot", "s3_bucket_object_versioning"},
}
