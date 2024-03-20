package main

type NistComp struct {
	Provider                  string
	Framework                 string
	Frameworkdesc             string
	Id                        string
	Description               string
	ItemId                    string
	WellArchitectedQuestionId string
	WellArchitectedPracticeId string
	Section                   string
	SubSection                string
	LevelOfRisk               string
	AssessmentMethod          string
	ImplementationGuidanceUrl string
	Checks                    []string
}

var frame_reliablity_REL09_BP03 = &NistComp{
	Framework:                 "AWS-Well-Architected-Framework-Reliability-Pillar",
	Provider:                  "AWS",
	Frameworkdesc:             "Best Practices for the AWS Well-Architected Framework Reliability Pillar encompasses the ability of a workload to perform its intended function correctly and consistently when it’s expected to. This includes the ability to operate and test the workload through its total lifecycle.",
	Id:                        "REL09-BP03",
	Description:               "Configure backups to be taken automatically based on a periodic schedule informed by the Recovery Point Objective (RPO), or by changes in the dataset. Critical datasets with low data loss requirements need to be backed up automatically on a frequent basis, whereas less critical data where some loss is acceptable can be backed up less frequently.",
	WellArchitectedQuestionId: "backing-up-data",
	WellArchitectedPracticeId: "rel_backing_up_data_automated_backups_data",
	Section:                   "Failure management",
	SubSection:                "Backup up data",
	LevelOfRisk:               "High",
	AssessmentMethod:          "Automated",
	ImplementationGuidanceUrl: "https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_backing_up_data_automated_backups_data.html#implementation-guidance",
	Checks:                    []string{"cloudformation_stacks_termination_protection_enabled", "rds_instance_backup_enabled", "rds_instance_deletion_protection", "dynamodb_tables_pitr_enabled"},
}
var frame_reliablity_REL06_BP01 = &NistComp{
	Framework:                 "AWS-Well-Architected-Framework-Reliability-Pillar",
	Provider:                  "AWS",
	Frameworkdesc:             "Best Practices for the AWS Well-Architected Framework Reliability Pillar encompasses the ability of a workload to perform its intended function correctly and consistently when it’s expected to. This includes the ability to operate and test the workload through its total lifecycle.",
	Id:                        "REL06-BP01",
	Description:               "Monitor components and services of AWS workload effectifely, using tools like Amazon CloudWatch and AWS Health Dashboard. Define relevant metrics, set thresholds, and analyze metrics and logs for early detection of issues.",
	WellArchitectedQuestionId: "monitor-aws-resources",
	WellArchitectedPracticeId: "rel_monitor_aws_resources_monitor_resources",
	Section:                   "Change management",
	SubSection:                "Monitor workload resources",
	LevelOfRisk:               "High",
	AssessmentMethod:          "Automated",
	ImplementationGuidanceUrl: "https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_monitor_aws_resources_monitor_resources.html#implementation-guidance",
	Checks:                    []string{"apigateway_restapi_logging_enabled", "apigatewayv2_api_access_logging_enabled", "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled", "cloudtrail_cloudwatch_logging_enabled", "elb_logging_enabled", "opensearch_service_domains_audit_logging_enabled", "opensearch_service_domains_cloudwatch_logging_enabled", "rds_instance_enhanced_monitoring_enabled", "rds_instance_integration_cloudwatch_logs"},
}
var frame_reliablity_REL10_BP01 = &NistComp{
	Framework:                 "AWS-Well-Architected-Framework-Reliability-Pillar",
	Provider:                  "AWS",
	Frameworkdesc:             "Best Practices for the AWS Well-Architected Framework Reliability Pillar encompasses the ability of a workload to perform its intended function correctly and consistently when it’s expected to. This includes the ability to operate and test the workload through its total lifecycle.",
	Id:                        "REL10-BP01",
	Description:               "Distribute workload data and resources across multiple Availability Zones or, where necessary, across AWS Regions. These locations can be as diverse as required.",
	WellArchitectedQuestionId: "fault-isolation",
	WellArchitectedPracticeId: "rel_fault_isolation_multiaz_region_system",
	Section:                   "Failure management",
	SubSection:                "Use fault isolation to protect your workload",
	LevelOfRisk:               "High",
	AssessmentMethod:          "Automated",
	ImplementationGuidanceUrl: "https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/use-fault-isolation-to-protect-your-workload.html#implementation-guidance.",
	Checks:                    []string{"rds_instance_multi_az"},
}
