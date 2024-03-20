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
	Service       string
	Checks        []string
}

var audit_1_0_1 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "1.0.1",
	Name:          "Disallow launch of EC2 instance types that are not EBS-optimized",
	Description:   "Checks whether EBS optimization is enabled for your EC2 instances that can be EBS-optimized",
	ItemId:        "1.0.1",
	Section:       "EBS checks",
	Service:       "ebs",
	Checks:        []string{},
}
var audit_1_0_2 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "1.0.2",
	Name:          "Disallow EBS volumes that are unattached to an EC2 instance",
	Description:   "Checks whether EBS volumes are attached to EC2 instances",
	ItemId:        "1.0.2",
	Section:       "EBS checks",
	Service:       "ebs",
	Checks:        []string{},
}
var audit_1_0_3 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "1.0.3",
	Name:          "Enable encryption for EBS volumes attached to EC2 instances",
	Description:   "Checks whether EBS volumes that are in an attached state are encrypted",
	ItemId:        "1.0.3",
	Section:       "EBS checks",
	Service:       "ebs",
	Checks:        []string{"ec2_ebs_default_encryption"},
}
var audit_2_0_1 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "2.0.1",
	Name:          "Disallow internet connection through RDP",
	Description:   "Checks whether security groups that are in use disallow unrestricted incoming TCP traffic to the specified",
	ItemId:        "2.0.1",
	Section:       "Disallow Internet Connection",
	Service:       "vpc",
	Checks:        []string{"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389"},
}
var audit_2_0_2 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "2.0.2",
	Name:          "Disallow internet connection through SSH",
	Description:   "Checks whether security groups that are in use disallow unrestricted incoming SSH traffic.",
	ItemId:        "2.0.2",
	Section:       "Disallow Internet Connection",
	Service:       "vpc",
	Checks:        []string{"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"},
}
var audit_3_0_1 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "3.0.1",
	Name:          "Disallow access to IAM users without MFA",
	Description:   "Checks whether the AWS Identity and Access Management users have multi-factor authentication (MFA) enabled.",
	ItemId:        "3.0.1",
	Section:       "Multi-Factor Authentication",
	Service:       "iam",
	Checks:        []string{"iam_user_mfa_enabled_console_access"},
}
var audit_3_0_2 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "3.0.2",
	Name:          "Disallow console access to IAM users without MFA",
	Description:   "Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password.",
	ItemId:        "3.0.2",
	Section:       "Multi-Factor Authentication",
	Service:       "iam",
	Checks:        []string{"iam_user_mfa_enabled_console_access"},
}
var audit_3_0_3 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "3.0.3",
	Name:          "Enable MFA for the root user",
	Description:   "Checks whether the root user of your AWS account requires multi-factor authentication for console sign-in.",
	ItemId:        "3.0.3",
	Section:       "Multi-Factor Authentication",
	Service:       "iam",
	Checks:        []string{"iam_root_mfa_enabled"},
}
var audit_4_0_1 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "4.0.1",
	Name:          "Disallow public access to RDS database instances",
	Description:   "Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible. The rule is non-compliant if the publiclyAccessible field is true in the instance configuration item.",
	ItemId:        "4.0.1",
	Section:       "Disallow Public Access",
	Service:       "rds",
	Checks:        []string{"rds_instance_no_public_access"},
}
var audit_4_0_2 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "4.0.2",
	Name:          "Disallow public access to RDS database snapshots",
	Description:   "Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public. The rule is non-compliant if any existing and new Amazon RDS snapshots are public.",
	ItemId:        "4.0.2",
	Section:       "Disallow Public Access",
	Service:       "rds",
	Checks:        []string{"rds_snapshots_public_access"},
}
var audit_4_1_1 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "4.1.1",
	Name:          "Disallow public read access to S3 buckets",
	Description:   "Checks that your S3 buckets do not allow public read access.",
	ItemId:        "4.1.1",
	Section:       "Disallow Public Access",
	Service:       "s3",
	Checks:        []string{"rds_instance_no_public_access"},
}
var audit_4_1_2 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "4.1.2",
	Name:          "Disallow public write access to S3 buckets",
	Description:   "Checks that your S3 buckets do not allow public write access.",
	ItemId:        "4.1.2",
	Section:       "Disallow Public Access",
	Service:       "s3",
	Checks:        []string{"s3_bucket_policy_public_write_access"},
}
var audit_5_0_1 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "5.0.1",
	Name:          "Disallow RDS database instances that are not storage encrypted ",
	Description:   "Checks whether storage encryption is enabled for your RDS DB instances.",
	ItemId:        "5.0.1",
	Section:       "Disallow Instances",
	Service:       "rds",
	Checks:        []string{"rds_instance_storage_encrypted"},
}
var audit_5_1_1 = &NistComp{
	Framework:     "AWS-Audit-Manager-Control-Tower-Guardrails",
	Provider:      "AWS",
	Frameworkdesc: "AWS Control Tower is a management and governance service that you can use to navigate through the setup process and governance requirements that are involved in creating a multi-account AWS environment.",
	Id:            "5.1.1",
	Name:          "Disallow S3 buckets that are not versioning enabled",
	Description:   "Checks whether versioning is enabled for your S3 buckets.",
	ItemId:        "5.1.1",
	Section:       "Disallow Instances",
	Service:       "s3",
	Checks:        []string{"s3_bucket_object_versioning"},
}
