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

var Nist_2_3_1_1 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_1",
	Name:          "3.1.1 Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems)",
	Description:   "Access control policies (e.g., identity or role-based policies, control matrices, and cryptography) control access between active entities or subjects (i.e., users or processes acting on behalf of users) and passive entities or objects (e.g., devices, files, records, and domains) in systems. Access enforcement mechanisms can be employed at the application and service level to provide increased information security. Other systems include systems internal and external to the organization. This requirement focuses on account management for systems and applications. The definition of and enforcement of access authorizations, other than those determined by account type (e.g., privileged verses non-privileged) are addressed in requirement 3.1.2.",
	Section:       "3.1 Access Control",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_profile_attached", "ec2_instance_public_ip", "eks_endpoints_not_publicly_accessible", "emr_cluster_master_nodes_no_public_ip", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_no_root_access_key", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access", "iam_user_accesskey_unused", "iam_user_console_access_unused", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_2_3_1_2 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_2",
	Name:          "3.1.2 Limit system access to the types of transactions and functions that authorized users are permitted to execute",
	Description:   "Organizations may choose to define access privileges or other attributes by account, by type of account, or a combination of both. System account types include individual, shared, group, system, anonymous, guest, emergency, developer, manufacturer, vendor, and temporary. Other attributes required for authorizing access include restrictions on time-of-day, day-of-week, and point-oforigin. In defining other account attributes, organizations consider system-related requirements (e.g., system upgrades scheduled maintenance,) and mission or business requirements, (e.g., time zone differences, customer requirements, remote access to support travel requirements).",
	Section:       "3.1 Access Control",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_profile_attached", "ec2_instance_public_ip", "eks_endpoints_not_publicly_accessible", "emr_cluster_master_nodes_no_public_ip", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_no_root_access_key", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access", "iam_user_accesskey_unused", "iam_user_console_access_unused", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_2_3_1_3 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_3",
	Name:          "3.1.3 Control the flow of CUI in accordance with approved authorizations",
	Description:   "Information flow control regulates where information can travel within a system and between systems (versus who can access the information) and without explicit regard to subsequent accesses to that information. Flow control restrictions include the following: keeping exportcontrolled information from being transmitted in the clear to the Internet; blocking outside traffic that claims to be from within the organization; restricting requests to the Internet that are not from the internal web proxy server; and limiting information transfers between organizations based on data structures and content. Organizations commonly use information flow control policies and enforcement mechanisms to control the flow of information between designated sources and destinations (e.g., networks, individuals, and devices) within systems and between interconnected systems. Flow control is based on characteristics of the information or the information path. Enforcement occurs in boundary protection devices (e.g., gateways, routers, guards, encrypted tunnels, firewalls) that employ rule sets or establish configuration settings that restrict system services, provide a packetfiltering capability based on header information, or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics). Organizations also consider the trustworthiness of filtering and inspection mechanisms (i.e., hardware, firmware, and software components) that are critical to information flow enforcement. Transferring information between systems representing different security domains with different security policies introduces risk that such transfers violate one or more domain security policies. In such situations, information owners or stewards provide guidance at designated policy enforcement points between interconnected systems. Organizations consider mandating specific architectural solutions when required to enforce specific security policies. Enforcement includes: prohibiting information transfers between interconnected systems (i.e., allowing access only); employing hardware mechanisms to enforce one-way information flows; and implementing trustworthy regrading mechanisms to reassign security attributes and security labels.",
	Section:       "3.1 Access Control",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "eks_endpoints_not_publicly_accessible", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_2_3_1_4 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_4",
	Name:          "3.1.4 Separate the duties of individuals to reduce the risk of malevolent activity without collusion",
	Description:   "Separation of duties addresses the potential for abuse of authorized privileges and helps to reduce the risk of malevolent activity without collusion. Separation of duties includes dividing mission functions and system support functions among different individuals or roles; conducting system support functions with different individuals (e.g., configuration management, quality assurance and testing, system management, programming, and network security); and ensuring that security personnel administering access control functions do not also administer audit functions. Because separation of duty violations can span systems and application domains, organizations consider the entirety of organizational systems and system components when developing policy on separation of duties.",
	Section:       "3.1 Access Control",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var Nist_2_3_1_5 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_5",
	Name:          "3.1.5 Employ the principle of least privilege, including for specific security functions and privileged accounts",
	Description:   "Organizations employ the principle of least privilege for specific duties and authorized accesses for users and processes. The principle of least privilege is applied with the goal of authorized privileges no higher than necessary to accomplish required organizational missions or business functions. Organizations consider the creation of additional processes, roles, and system accounts as necessary, to achieve least privilege. Organizations also apply least privilege to the development, implementation, and operation of organizational systems. Security functions include establishing system accounts, setting events to be logged, setting intrusion detection parameters, and configuring access authorizations (i.e., permissions, privileges). Privileged accounts, including super user accounts, are typically described as system administrator for various types of commercial off-the-shelf operating systems. Restricting privileged accounts to specific personnel or roles prevents day-to-day users from having access to privileged information or functions. Organizations may differentiate in the application of this requirement between allowed privileges for local accounts and for domain accounts provided organizations retain the ability to control system configurations for key security parameters and as otherwise necessary to sufficiently mitigate risk.",
	Section:       "3.1 Access Control",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var Nist_2_3_1_6 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_6",
	Name:          "3.1.6 Use non-privileged accounts or roles when accessing nonsecurity functions",
	Description:   "This requirement limits exposure when operating from within privileged accounts or roles. The inclusion of roles addresses situations where organizations implement access control policies such as role-based access control and where a change of role provides the same degree of assurance in the change of access authorizations for the user and all processes acting on behalf of the user as would be provided by a change between a privileged and non-privileged account.",
	Section:       "3.1 Access Control",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key"},
}
var Nist_2_3_1_7 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_7",
	Name:          "3.1.7 Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs",
	Description:   "Privileged functions include establishing system accounts, performing system integrity checks, conducting patching operations, or administering cryptographic key management activities. Nonprivileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users. Note that this requirement represents a condition to be achieved by the definition of authorized privileges in 3.1.2. Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Logging the use of privileged functions is one way to detect such misuse, and in doing so, help mitigate the risk from insider threats and the advanced persistent threat.",
	Section:       "3.1 Access Control",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key"},
}
var Nist_2_3_1_12 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_12",
	Name:          "3.1.12 Monitor and control remote access sessions",
	Description:   "Remote access is access to organizational systems by users (or processes acting on behalf of users) communicating through external networks (e.g., the Internet). Remote access methods include dial-up, broadband, and wireless. Organizations often employ encrypted virtual private networks (VPNs) to enhance confidentiality over remote connections. The use of encrypted VPNs does not make the access non-remote; however, the use of VPNs, when adequately provisioned with appropriate control (e.g., employing encryption techniques for confidentiality protection), may provide sufficient assurance to the organization that it can effectively treat such connections as internal networks. VPNs with encrypted tunnels can affect the capability to adequately monitor network communications traffic for malicious code. Automated monitoring and control of remote access sessions allows organizations to detect cyberattacks and help to ensure ongoing compliance with remote access policies by auditing connection activities of remote users on a variety of system components (e.g., servers, workstations, notebook computers, smart phones, and tablets).",
	Section:       "3.1 Access Control",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "guardduty_is_enabled", "rds_instance_integration_cloudwatch_logs", "s3_bucket_server_access_logging_enabled", "securityhub_enabled"},
}
var Nist_2_3_1_13 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_13",
	Name:          "3.1.13 Employ cryptographic mechanisms to protect the confidentiality of remote access sessions",
	Description:   "Cryptographic standards include FIPS-validated cryptography and NSA-approved cryptography.",
	Section:       "3.1 Access Control",
	Checks:        []string{"elb_ssl_listeners", "s3_bucket_secure_transport_policy"},
}
var Nist_2_3_1_14 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_14",
	Name:          "3.1.14 Route remote access via managed access control points",
	Description:   "Routing remote access through managed access control points enhances explicit, organizational control over such connections, reducing the susceptibility to unauthorized access to organizational systems resulting in the unauthorized disclosure of CUI.",
	Section:       "3.1 Access Control",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "iam_user_mfa_enabled_console_access", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_2_3_1_20 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_1_20",
	Name:          "3.1.20 Verify and control/limit connections to and use of external systems",
	Description:   "External systems are systems or components of systems for which organizations typically have no direct supervision and authority over the application of security requirements and controls or the determination of the effectiveness of implemented controls on those systems. External systems include personally owned systems, components, or devices and privately-owned computing and communications devices resident in commercial or public facilities. This requirement also addresses the use of external systems for the processing, storage, or transmission of CUI, including accessing cloud services (e.g., infrastructure as a service, platform as a service, or software as a service) from organizational systems. Organizations establish terms and conditions for the use of external systems in accordance with organizational security policies and procedures. Terms and conditions address as a minimum, the types of applications that can be accessed on organizational systems from external systems. If terms and conditions with the owners of external systems cannot be established, organizations may impose restrictions on organizational personnel using those external systems. This requirement recognizes that there are circumstances where individuals using external systems (e.g., contractors, coalition partners) need to access organizational systems. In those situations, organizations need confidence that the external systems contain the necessary controls so as not to compromise, damage, or otherwise harm organizational systems. Verification that the required controls have been effectively implemented can be achieved by third-party, independent assessments, attestations, or other means, depending on the assurance or confidence level required by organizations. Note that while “external” typically refers to outside of the organization's direct supervision and authority, that is not always the case. Regarding the protection of CUI across an organization, the organization may have systems that process CUI and others that do not. And among the systems that process CUI there are likely access restrictions for CUI that apply between systems. Therefore, from the perspective of a given system, other systems within the organization may be considered 'external' to that system.",
	Section:       "3.1 Access Control",
	Checks:        []string{"s3_account_level_public_access_blocks", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_2_3_3_1 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_3_1",
	Name:          "3.3.1 Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity",
	Description:   "An event is any observable occurrence in a system, which includes unlawful or unauthorized system activity. Organizations identify event types for which a logging functionality is needed as those events which are significant and relevant to the security of systems and the environments in which those systems operate to meet specific and ongoing auditing needs. Event types can include password changes, failed logons or failed accesses related to systems, administrative privilege usage, or third-party credential usage. In determining event types that require logging, organizations consider the monitoring and auditing appropriate for each of the CUI security requirements. Monitoring and auditing requirements can be balanced with other system needs. For example, organizations may determine that systems must have the capability to log every file access both successful and unsuccessful, but not activate that capability except for specific circumstances due to the potential burden on system performance. Audit records can be generated at various levels of abstraction, including at the packet level as information traverses the network. Selecting the appropriate level of abstraction is a critical aspect of an audit logging capability and can facilitate the identification of root causes to problems. Organizations consider in the definition of event types, the logging necessary to cover related events such as the steps in distributed, transaction-based processes (e.g., processes that are distributed across multiple organizations) and actions that occur in service-oriented or cloudbased architectures. Audit record content that may be necessary to satisfy this requirement includes time stamps, source and destination addresses, user or process identifiers, event descriptions, success or fail indications, filenames involved, and access control or flow control rules invoked. Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the system after the event occurred). Detailed information that organizations may consider in audit records includes full text recording of privileged commands or the individual identities of group account users. Organizations consider limiting the additional audit log information to only that information explicitly needed for specific audit requirements. This facilitates the use of audit trails and audit logs by not including information that could potentially be misleading or could make it more difficult to locate information of interest. Audit logs are reviewed and analyzed as often as needed to provide important information to organizations to facilitate risk-based decision making.",
	Section:       "3.3 Audit and Accountability",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "cloudwatch_log_group_retention_policy_specific_days_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "guardduty_is_enabled", "rds_instance_integration_cloudwatch_logs", "s3_bucket_server_access_logging_enabled", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
var Nist_2_3_3_2 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_3_2",
	Name:          "3.3.2 Ensure that the actions of individual system users can be uniquely traced to those users, so they can be held accountable for their actions",
	Description:   "This requirement ensures that the contents of the audit record include the information needed to link the audit event to the actions of an individual to the extent feasible. Organizations consider logging for traceability including results from monitoring of account usage, remote access, wireless connectivity, mobile device connection, communications at system boundaries, configuration settings, physical access, nonlocal maintenance, use of maintenance tools, temperature and humidity, equipment delivery and removal, system component inventory, use of mobile code, and use of Voice over Internet Protocol (VoIP).",
	Section:       "3.3 Audit and Accountability",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "guardduty_is_enabled", "rds_instance_integration_cloudwatch_logs", "s3_bucket_server_access_logging_enabled"},
}
var Nist_2_3_3_3 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_3_3",
	Name:          "3.3.3 Review and update logged events",
	Description:   "The intent of this requirement is to periodically re-evaluate which logged events will continue to be included in the list of events to be logged. The event types that are logged by organizations may change over time. Reviewing and updating the set of logged event types periodically is necessary to ensure that the current set remains necessary and sufficient.",
	Section:       "3.3 Audit and Accountability",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "rds_instance_integration_cloudwatch_logs", "s3_bucket_server_access_logging_enabled", "vpc_flow_logs_enabled"},
}
var Nist_2_3_3_4 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_3_4",
	Name:          "3.3.4 Alert in the event of an audit logging process failure",
	Description:   "Audit logging process failures include software and hardware errors, failures in the audit record capturing mechanisms, and audit record storage capacity being reached or exceeded. This requirement applies to each audit record data storage repository (i.e., distinct system component where audit records are stored), the total audit record storage capacity of organizations (i.e., all audit record data storage repositories combined), or both.",
	Section:       "3.3 Audit and Accountability",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var Nist_2_3_3_5 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_3_5",
	Name:          "3.3.5 Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity",
	Description:   "Correlating audit record review, analysis, and reporting processes helps to ensure that they do not operate independently, but rather collectively. Regarding the assessment of a given organizational system, the requirement is agnostic as to whether this correlation is applied at the system level or at the organization level across all systems.",
	Section:       "3.3 Audit and Accountability",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "guardduty_is_enabled", "securityhub_enabled"},
}
var Nist_2_3_3_8 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_3_8",
	Name:          "3.3.8 Protect audit information and audit logging tools from unauthorized access, modification, and deletion",
	Description:   "Audit information includes all information (e.g., audit records, audit log settings, and audit reports) needed to successfully audit system activity. Audit logging tools are those programs and devices used to conduct audit and logging activities. This requirement focuses on the technical protection of audit information and limits the ability to access and execute audit logging tools to authorized individuals. Physical protection of audit information is addressed by media protection and physical and environmental protection requirements.",
	Section:       "3.3 Audit and Accountability",
	Checks:        []string{"cloudtrail_kms_encryption_enabled", "cloudtrail_log_file_validation_enabled", "cloudwatch_log_group_kms_encryption_enabled", "s3_bucket_default_encryption", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_bucket_object_versioning", "s3_account_level_public_access_blocks"},
}
var Nist_2_3_4_1 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_4_1",
	Name:          "3.4.1 Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles",
	Description:   "Baseline configurations are documented, formally reviewed, and agreed-upon specifications for systems or configuration items within those systems. Baseline configurations serve as a basis for future builds, releases, and changes to systems. Baseline configurations include information about system components (e.g., standard software packages installed on workstations, notebook computers, servers, network components, or mobile devices; current version numbers and update and patch information on operating systems and applications; and configuration settings and parameters), network topology, and the logical placement of those components within the system architecture. Baseline configurations of systems also reflect the current enterprise architecture. Maintaining effective baseline configurations requires creating new baselines as organizational systems change over time. Baseline configuration maintenance includes reviewing and updating the baseline configuration when changes are made based on security risks and deviations from the established baseline configuration Organizations can implement centralized system component inventories that include components from multiple organizational systems. In such situations, organizations ensure that the resulting inventories include system-specific information required for proper component accountability (e.g., system association, system owner). Information deemed necessary for effective accountability of system components includes hardware inventory specifications, software license information, software version numbers, component owners, and for networked components or devices, machine names and network addresses. Inventory specifications include manufacturer, device type, model, serial number, and physical location.",
	Section:       "3.4 Configuration Management",
	Checks:        []string{"cloudtrail_multi_region_enabled", "ec2_instance_managed_by_ssm", "ec2_instance_older_than_specific_days", "elbv2_deletion_protection", "ssm_managed_compliant_patching", "ec2_elastic_ip_unassigned", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_2_3_4_2 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_4_2",
	Name:          "3.4.2 Establish and enforce security configuration settings for information technology products employed in organizational systems",
	Description:   "Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture or functionality of the system. Information technology products for which security-related configuration settings can be defined include mainframe computers, servers, workstations, input and output devices (e.g., scanners, copiers, and printers), network components (e.g., firewalls, routers, gateways, voice and data switches, wireless access points, network appliances, sensors), operating systems, middleware, and applications. Security parameters are those parameters impacting the security state of systems including the parameters required to satisfy other security requirements. Security parameters include: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, and remote connections. Organizations establish organization-wide configuration settings and subsequently derive specific configuration settings for systems. The established settings become part of the systems configuration baseline. Common secure configurations (also referred to as security configuration checklists, lockdown and hardening guides, security reference guides, security technical implementation guides) provide recognized, standardized, and established benchmarks that stipulate secure configuration settings for specific information technology platforms/products and instructions for configuring those system components to meet operational requirements. Common secure configurations can be developed by a variety of organizations including information technology product developers, manufacturers, vendors, consortia, academia, industry, federal agencies, and other organizations in the public and private sectors.",
	Section:       "3.4 Configuration Management",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ec2_instance_older_than_specific_days", "ssm_managed_compliant_patching"},
}
var Nist_2_3_4_6 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_4_6",
	Name:          "3.4.6 Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities",
	Description:   "Systems can provide a wide variety of functions and services. Some of the functions and services routinely provided by default, may not be necessary to support essential organizational missions, functions, or operations. It is sometimes convenient to provide multiple services from single system components. However, doing so increases risk over limiting the services provided by any one component. Where feasible, organizations limit component functionality to a single function per component. Organizations review functions and services provided by systems or components of systems, to determine which functions and services are candidates for elimination. Organizations disable unused or unnecessary physical and logical ports and protocols to prevent unauthorized connection of devices, transfer of information, and tunneling. Organizations can utilize network scanning tools, intrusion detection and prevention systems, and end-point protections such as firewalls and host-based intrusion detection systems to identify and prevent the use of prohibited functions, ports, protocols, and services.",
	Section:       "3.4 Configuration Management",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_managed_by_ssm", "iam_policy_attached_only_to_group_or_roles", "iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges", "iam_no_root_access_key", "awslambda_function_url_public", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "ssm_managed_compliant_patching", "ec2_securitygroup_default_restrict_traffic"},
}
var Nist_2_3_4_7 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_4_7",
	Name:          "3.4.7 Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services",
	Description:   "Restricting the use of nonessential software (programs) includes restricting the roles allowed to approve program execution; prohibiting auto-execute; program blacklisting and whitelisting; or restricting the number of program instances executed at the same time. The organization makes a security-based determination which functions, ports, protocols, and/or services are restricted. Bluetooth, File Transfer Protocol (FTP), and peer-to-peer networking are examples of protocols organizations consider preventing the use of, restricting, or disabling.",
	Section:       "3.4 Configuration Management",
	Checks:        []string{"ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_2_3_4_9 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_4_9",
	Name:          "3.4.9 Control and monitor user-installed software",
	Description:   "Users can install software in organizational systems if provided the necessary privileges. To maintain control over the software installed, organizations identify permitted and prohibited actions regarding software installation through policies. Permitted software installations include updates and security patches to existing software and applications from organization-approved 'app stores.' Prohibited software installations may include software with unknown or suspect pedigrees or software that organizations consider potentially malicious. The policies organizations select governing user-installed software may be organization-developed or provided by some external entity. Policy enforcement methods include procedural methods, automated methods, or both.",
	Section:       "3.4 Configuration Management",
	Checks:        []string{"ec2_instance_managed_by_ssm", "ssm_managed_compliant_patching"},
}
var Nist_2_3_5_2 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_5_2",
	Name:          "3.5.2 Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems",
	Description:   "Individual authenticators include the following: passwords, key cards, cryptographic devices, and one-time password devices. Initial authenticator content is the actual content of the authenticator, for example, the initial password. In contrast, the requirements about authenticator content include the minimum password length. Developers ship system components with factory default authentication credentials to allow for initial installation and configuration. Default authentication credentials are often well known, easily discoverable, and present a significant security risk. Systems support authenticator management by organization-defined settings and restrictions for various authenticator characteristics including minimum password length, validation time window for time synchronous one-time tokens, and number of allowed rejections during the verification stage of biometric authentication. Authenticator management includes issuing and revoking, when no longer needed, authenticators for temporary access such as that required for remote maintenance. Device authenticators include certificates and passwords.",
	Section:       "3.5 Identification and Authentication",
	Checks:        []string{"iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access"},
}
var Nist_2_3_5_3 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_5_3",
	Name:          "3.5.3 Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts",
	Description:   "Multifactor authentication requires the use of two or more different factors to authenticate. The factors are defined as something you know (e.g., password, personal identification number [PIN]); something you have (e.g., cryptographic identification device, token); or something you are (e.g., biometric). Multifactor authentication solutions that feature physical authenticators include hardware authenticators providing time-based or challenge-response authenticators and smart cards. In addition to authenticating users at the system level (i.e., at logon), organizations may also employ authentication mechanisms at the application level, when necessary, to provide increased information security. Access to organizational systems is defined as local access or network access. Local access is any access to organizational systems by users (or processes acting on behalf of users) where such access is obtained by direct connections without the use of networks. Network access is access to systems by users (or processes acting on behalf of users) where such access is obtained through network connections (i.e., nonlocal accesses). Remote access is a type of network access that involves communication through external networks. The use of encrypted virtual private networks for connections between organization-controlled and non-organization controlled endpoints may be treated as internal networks with regard to protecting the confidentiality of information.",
	Section:       "3.5 Identification and Authentication",
	Checks:        []string{"iam_root_hardware_mfa_enabled", "iam_root_mfa_enabled", "iam_user_mfa_enabled_console_access", "iam_user_mfa_enabled_console_access"},
}
var Nist_2_3_5_5 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_5_5",
	Name:          "3.5.5 Prevent reuse of identifiers for a defined period",
	Description:   "Identifiers are provided for users, processes acting on behalf of users, or devices (3.5.1). Preventing reuse of identifiers implies preventing the assignment of previously used individual, group, role, or device identifiers to different individuals, groups, roles, or devices.",
	Section:       "3.5 Identification and Authentication",
	Checks:        []string{"iam_password_policy_reuse_24", "iam_password_policy_expires_passwords_within_90_days_or_less"},
}
var Nist_2_3_5_6 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_5_6",
	Name:          "3.5.6 Disable identifiers after a defined period of inactivity",
	Description:   "Inactive identifiers pose a risk to organizational information because attackers may exploit an inactive identifier to gain undetected access to organizational devices. The owners of the inactive accounts may not notice if unauthorized access to the account has been obtained.",
	Section:       "3.5 Identification and Authentication",
	Checks:        []string{"iam_password_policy_reuse_24", "iam_password_policy_expires_passwords_within_90_days_or_less", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var Nist_2_3_5_7 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_5_7",
	Name:          "3.5.7 Enforce a minimum password complexity and change of characters when new passwords are created",
	Description:   "This requirement applies to single-factor authentication of individuals using passwords as individual or group authenticators, and in a similar manner, when passwords are used as part of multifactor authenticators. The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. To mitigate certain brute force attacks against passwords, organizations may also consider salting passwords.",
	Section:       "3.5 Identification and Authentication",
	Checks:        []string{"iam_password_policy_minimum_length_14", "iam_password_policy_lowercase", "iam_password_policy_number", "iam_password_policy_symbol", "iam_password_policy_uppercase", "iam_password_policy_reuse_24", "iam_password_policy_expires_passwords_within_90_days_or_less", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var Nist_2_3_5_8 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_5_8",
	Name:          "3.5.8 Prohibit password reuse for a specified number of generations",
	Description:   "Password lifetime restrictions do not apply to temporary passwords.",
	Section:       "3.5 Identification and Authentication",
	Checks:        []string{"iam_password_policy_reuse_24", "iam_password_policy_expires_passwords_within_90_days_or_less", "iam_user_accesskey_unused", "iam_user_console_access_unused"},
}
var Nist_2_3_5_10 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_5_10",
	Name:          "3.5.10 Store and transmit only cryptographically-protected passwords",
	Description:   "Cryptographically-protected passwords use salted one-way cryptographic hashes of passwords.",
	Section:       "3.5 Identification and Authentication",
	Checks:        []string{"apigateway_restapi_client_certificate_enabled", "ec2_ebs_volume_encryption", "elbv2_insecure_ssl_ciphers", "opensearch_service_domains_node_to_node_encryption_enabled", "s3_bucket_default_encryption", "s3_bucket_secure_transport_policy"},
}
var Nist_2_3_6_1 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_6_1",
	Name:          "3.6.1 Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities",
	Description:   "Organizations recognize that incident handling capability is dependent on the capabilities of organizational systems and the mission/business processes being supported by those systems. Organizations consider incident handling as part of the definition, design, and development of mission/business processes and systems. Incident-related information can be obtained from a variety of sources including audit monitoring, network monitoring, physical access monitoring, user and administrator reports, and reported supply chain events. Effective incident handling capability includes coordination among many organizational entities including mission/business owners, system owners, authorizing officials, human resources offices, physical and personnel security offices, legal departments, operations personnel, procurement offices, and the risk executive. As part of user response activities, incident response training is provided by organizations and is linked directly to the assigned roles and responsibilities of organizational personnel to ensure that the appropriate content and level of detail is included in such training. For example, regular users may only need to know who to call or how to recognize an incident on the system; system administrators may require additional training on how to handle or remediate incidents; and incident responders may receive more specific training on forensics, reporting, system recovery, and restoration. Incident response training includes user training in the identification/reporting of suspicious activities from external and internal sources. User response activities also includes incident response assistance which may consist of help desk support, assistance groups, and access to forensics services or consumer redress services, when required.",
	Section:       "3.6 Incident Response",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "cloudwatch_log_group_retention_policy_specific_days_enabled", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "rds_instance_integration_cloudwatch_logs", "s3_bucket_server_access_logging_enabled", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
var Nist_2_3_6_2 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_6_2",
	Name:          "3.6.2 Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization",
	Description:   "Tracking and documenting system security incidents includes maintaining records about each incident, the status of the incident, and other pertinent information necessary for forensics, evaluating incident details, trends, and handling. Incident information can be obtained from a variety of sources including incident reports, incident response teams, audit monitoring, network monitoring, physical access monitoring, and user/administrator reports. Reporting incidents addresses specific incident reporting requirements within an organization and the formal incident reporting requirements for the organization. Suspected security incidents may also be reported and include the receipt of suspicious email communications that can potentially contain malicious code. The types of security incidents reported, the content and timeliness of the reports, and the designated reporting authorities reflect applicable laws, Executive Orders, directives, regulations, and policies.",
	Section:       "3.6 Incident Response",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "cloudwatch_log_group_retention_policy_specific_days_enabled", "guardduty_is_enabled", "guardduty_no_high_severity_findings", "rds_instance_integration_cloudwatch_logs", "s3_bucket_server_access_logging_enabled", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
var Nist_2_3_11_2 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_11_2",
	Name:          "3.11.2 Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified",
	Description:   "Organizations determine the required vulnerability scanning for all system components, ensuring that potential sources of vulnerabilities such as networked printers, scanners, and copiers are not overlooked. The vulnerabilities to be scanned are readily updated as new vulnerabilities are discovered, announced, and scanning methods developed. This process ensures that potential vulnerabilities in the system are identified and addressed as quickly as possible. Vulnerability analyses for custom software applications may require additional approaches such as static analysis, dynamic analysis, binary analysis, or a hybrid of the three approaches. Organizations can employ these analysis approaches in source code reviews and in a variety of tools (e.g., static analysis tools, web-based application scanners, binary analyzers) and in source code reviews. Vulnerability scanning includes: scanning for patch levels; scanning for functions, ports, protocols, and services that should not be accessible to users or devices; and scanning for improperly configured or incorrectly operating information flow control mechanisms. To facilitate interoperability, organizations consider using products that are Security Content Automated Protocol (SCAP)-validated, scanning tools that express vulnerabilities in the Common Vulnerabilities and Exposures (CVE) naming convention, and that employ the Open Vulnerability Assessment Language (OVAL) to determine the presence of system vulnerabilities. Sources for vulnerability information include the Common Weakness Enumeration (CWE) listing and the National Vulnerability Database (NVD). Security assessments, such as red team exercises, provide additional sources of potential vulnerabilities for which to scan. Organizations also consider using scanning tools that express vulnerability impact by the Common Vulnerability Scoring System (CVSS). In certain situations, the nature of the vulnerability scanning may be more intrusive or the system component that is the subject of the scanning may contain highly sensitive information. Privileged access authorization to selected system components facilitates thorough vulnerability scanning and protects the sensitive nature of such scanning.",
	Section:       "3.11 Risk Assessment",
	Checks:        []string{"guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var Nist_2_3_11_3 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_11_3",
	Name:          "3.11.3 Remediate vulnerabilities in accordance with risk assessments",
	Description:   "Vulnerabilities discovered, for example, via the scanning conducted in response to 3.11.2, are remediated with consideration of the related assessment of risk. The consideration of risk influences the prioritization of remediation efforts and the level of effort to be expended in the remediation for specific vulnerabilities.",
	Section:       "3.11 Risk Assessment",
	Checks:        []string{"guardduty_is_enabled", "guardduty_no_high_severity_findings", "securityhub_enabled"},
}
var Nist_2_3_12_4 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_12_4",
	Name:          "3.12.4 Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems",
	Description:   "System security plans relate security requirements to a set of security controls. System security plans also describe, at a high level, how the security controls meet those security requirements, but do not provide detailed, technical descriptions of the design or implementation of the controls. System security plans contain sufficient information to enable a design and implementation that is unambiguously compliant with the intent of the plans and subsequent determinations of risk if the plan is implemented as intended. Security plans need not be single documents; the plans can be a collection of various documents including documents that already exist. Effective security plans make extensive use of references to policies, procedures, and additional documents (e.g., design and implementation specifications) where more detailed information can be obtained. This reduces the documentation requirements associated with security programs and maintains security-related information in other established management/operational areas related to enterprise architecture, system development life cycle, systems engineering, and acquisition. Federal agencies may consider the submitted system security plans and plans of action as critical inputs to an overall risk management decision to process, store, or transmit CUI on a system hosted by a nonfederal organization and whether it is advisable to pursue an agreement or contract with the nonfederal organization.",
	Section:       "3.12 Assessment, Authorization, and Monitoring",
	Checks:        []string{"cloudtrail_cloudwatch_logging_enabled", "cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "ec2_instance_imdsv2_enabled", "guardduty_is_enabled", "rds_instance_enhanced_monitoring_enabled", "securityhub_enabled"},
}
var Nist_2_3_13_1 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_13_1",
	Name:          "3.13.1 Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems",
	Description:   "Communications can be monitored, controlled, and protected at boundary components and by restricting or prohibiting interfaces in organizational systems. Boundary components include gateways, routers, firewalls, guards, network-based malicious code analysis and virtualization systems, or encrypted tunnels implemented within a system security architecture (e.g., routers protecting firewalls or application gateways residing on protected subnetworks). Restricting or prohibiting interfaces in organizational systems includes restricting external web communications traffic to designated web servers within managed interfaces and prohibiting external traffic that appears to be spoofing internal addresses. Organizations consider the shared nature of commercial telecommunications services in the implementation of security requirements associated with the use of such services. Commercial telecommunications services are commonly based on network components and consolidated management systems shared by all attached commercial customers and may also include third party-provided access lines and other service elements. Such transmission services may represent sources of increased risk despite contract security provisions.",
	Section:       "3.13 System and Communications Protection",
	Checks:        []string{"acm_certificates_expiration_check", "apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_log_file_validation_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "elbv2_waf_acl_attached", "elb_ssl_listeners", "guardduty_is_enabled", "awslambda_function_not_publicly_accessible", "rds_instance_integration_cloudwatch_logs", "rds_instance_no_public_access", "redshift_cluster_public_access", "s3_bucket_secure_transport_policy", "s3_bucket_server_access_logging_enabled", "securityhub_enabled", "vpc_flow_logs_enabled", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_2_3_13_2 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_13_2",
	Name:          "3.13.2 Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems",
	Description:   "Organizations apply systems security engineering principles to new development systems or systems undergoing major upgrades. For legacy systems, organizations apply systems security engineering principles to system upgrades and modifications to the extent feasible, given the current state of hardware, software, and firmware components within those systems. The application of systems security engineering concepts and principles helps to develop trustworthy, secure, and resilient systems and system components and reduce the susceptibility of organizations to disruptions, hazards, and threats. Examples of these concepts and principles include developing layered protections; establishing security policies, architecture, and controls as the foundation for design; incorporating security requirements into the system development life cycle; delineating physical and logical security boundaries; ensuring that developers are trained on how to build secure software; and performing threat modeling to identify use cases, threat agents, attack vectors and patterns, design patterns, and compensating controls needed to mitigate risk. Organizations that apply security engineering concepts and principles can facilitate the development of trustworthy, secure systems, system components, and system services; reduce risk to acceptable levels; and make informed risk-management decisions.",
	Section:       "3.13 System and Communications Protection",
	Checks:        []string{"acm_certificates_expiration_check", "cloudtrail_multi_region_enabled", "dynamodb_tables_pitr_enabled", "ec2_ebs_public_snapshot", "ec2_instance_public_ip", "efs_have_backup_enabled", "elbv2_deletion_protection", "emr_cluster_master_nodes_no_public_ip", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_backup_enabled", "rds_instance_integration_cloudwatch_logs", "rds_instance_multi_az", "rds_instance_no_public_access", "rds_instance_backup_enabled", "redshift_cluster_public_access", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"},
}
var Nist_2_3_13_3 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_13_3",
	Name:          "3.13.3 Separate user functionality from system management functionality",
	Description:   "System management functionality includes functions necessary to administer databases, network components, workstations, or servers, and typically requires privileged user access. The separation of user functionality from system management functionality is physical or logical. Organizations can implement separation of system management functionality from user functionality by using different computers, different central processing units, different instances of operating systems, or different network addresses; virtualization techniques; or combinations of these or other methods, as appropriate. This type of separation includes web administrative interfaces that use separate authentication methods for users of any other system resources. Separation of system and user functionality may include isolating administrative interfaces on different domains and with additional access controls.",
	Section:       "3.13 System and Communications Protection",
	Checks:        []string{"iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges", "iam_inline_policy_no_administrative_privileges"},
}
var Nist_2_3_13_4 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_13_4",
	Name:          "3.13.4 Prevent unauthorized and unintended information transfer via shared system resources",
	Description:   "The control of information in shared system resources (e.g., registers, cache memory, main memory, hard disks) is also commonly referred to as object reuse and residual information protection. This requirement prevents information produced by the actions of prior users or roles (or the actions of processes acting on behalf of prior users or roles) from being available to any current users or roles (or current processes acting on behalf of current users or roles) that obtain access to shared system resources after those resources have been released back to the system. This requirement also applies to encrypted representations of information. This requirement does not address information remanence, which refers to residual representation of data that has been nominally deleted; covert channels (including storage or timing channels) where shared resources are manipulated to violate information flow restrictions; or components within systems for which there are only single users or roles.",
	Section:       "3.13 System and Communications Protection",
	Checks:        []string{},
}
var Nist_2_3_13_5 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_13_5",
	Name:          "3.13.5 Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks",
	Description:   "Subnetworks that are physically or logically separated from internal networks are referred to as demilitarized zones (DMZs). DMZs are typically implemented with boundary control devices and techniques that include routers, gateways, firewalls, virtualization, or cloud-based technologies.",
	Section:       "3.13 System and Communications Protection",
	Checks:        []string{"ec2_ebs_public_snapshot", "ec2_instance_public_ip", "elbv2_waf_acl_attached", "elb_ssl_listeners", "emr_cluster_master_nodes_no_public_ip", "opensearch_service_domains_node_to_node_encryption_enabled", "awslambda_function_not_publicly_accessible", "awslambda_function_url_public", "rds_instance_no_public_access", "rds_snapshots_public_access", "redshift_cluster_public_access", "s3_bucket_secure_transport_policy", "s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_account_level_public_access_blocks", "sagemaker_notebook_instance_without_direct_internet_access_configured", "ec2_securitygroup_default_restrict_traffic", "ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_2_3_13_6 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_13_6",
	Name:          "3.13.6 Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception)",
	Description:   "This requirement applies to inbound and outbound network communications traffic at the system boundary and at identified points within the system. A deny-all, permit-by-exception network communications traffic policy ensures that only those connections which are essential and approved are allowed.",
	Section:       "3.13 System and Communications Protection",
	Checks:        []string{"ec2_networkacl_allow_ingress_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_networkacl_allow_ingress_any_port"},
}
var Nist_2_3_13_8 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_13_8",
	Name:          "3.13.8 Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards",
	Description:   "This requirement applies to internal and external networks and any system components that can transmit information including servers, notebook computers, desktop computers, mobile devices, printers, copiers, scanners, and facsimile machines. Communication paths outside the physical protection of controlled boundaries are susceptible to both interception and modification. Organizations relying on commercial providers offering transmission services as commodity services rather than as fully dedicated services (i.e., services which can be highly specialized to individual customer needs), may find it difficult to obtain the necessary assurances regarding the implementation of the controls for transmission confidentiality. In such situations, organizations determine what types of confidentiality services are available in commercial telecommunication service packages. If it is infeasible or impractical to obtain the necessary safeguards and assurances of the effectiveness of the safeguards through appropriate contracting vehicles, organizations implement compensating safeguards or explicitly accept the additional risk. An example of an alternative physical safeguard is a protected distribution system (PDS) where the distribution medium is protected against electronic or physical intercept, thereby ensuring the confidentiality of the information being transmitted.",
	Section:       "3.13 System and Communications Protection",
	Checks:        []string{"acm_certificates_expiration_check", "elb_ssl_listeners", "opensearch_service_domains_node_to_node_encryption_enabled", "s3_bucket_secure_transport_policy"},
}
var Nist_2_3_13_11 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_13_11",
	Name:          "3.13.11 Employ FIPS-validated cryptography when used to protect the confidentiality of CUI",
	Description:   "Cryptography can be employed to support many security solutions including the protection of controlled unclassified information, the provision of digital signatures, and the enforcement of information separation when authorized individuals have the necessary clearances for such information but lack the necessary formal access approvals. Cryptography can also be used to support random number generation and hash generation. Cryptographic standards include FIPSvalidated cryptography and/or NSA-approved cryptography.",
	Section:       "3.13 System and Communications Protection",
	Checks:        []string{"acm_certificates_expiration_check", "cloudtrail_kms_encryption_enabled", "dynamodb_tables_kms_cmk_encryption_enabled", "ec2_ebs_volume_encryption", "efs_encryption_at_rest_enabled", "opensearch_service_domains_encryption_at_rest_enabled", "cloudwatch_log_group_kms_encryption_enabled", "rds_instance_storage_encrypted", "s3_bucket_default_encryption", "s3_bucket_secure_transport_policy", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled"},
}
var Nist_2_3_13_15 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_13_15",
	Name:          "3.13.15 Protect the authenticity of communications sessions",
	Description:   "Authenticity protection includes protecting against man-in-the-middle attacks, session hijacking, and the insertion of false information into communications sessions. This requirement addresses communications protection at the session versus packet level (e.g., sessions in service-oriented architectures providing web-based services) and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted.",
	Section:       "3.13 System and Communications Protection",
	Checks:        []string{"elb_ssl_listeners"},
}
var Nist_2_3_13_16 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_13_16",
	Name:          "3.13.16 Protect the confidentiality of CUI at rest",
	Description:   "Information at rest refers to the state of information when it is not in process or in transit and is located on storage devices as specific components of systems. The focus of protection at rest is not on the type of storage device or the frequency of access but rather the state of the information. Organizations can use different mechanisms to achieve confidentiality protections, including the use of cryptographic mechanisms and file share scanning. Organizations may also use other controls including secure off-line storage in lieu of online storage when adequate protection of information at rest cannot otherwise be achieved or continuous monitoring to identify malicious code at rest.",
	Section:       "3.13 System and Communications Protection",
	Checks:        []string{"cloudtrail_kms_encryption_enabled", "dynamodb_tables_kms_cmk_encryption_enabled", "dynamodb_tables_kms_cmk_encryption_enabled", "ec2_ebs_volume_encryption", "efs_encryption_at_rest_enabled", "opensearch_service_domains_encryption_at_rest_enabled", "cloudwatch_log_group_kms_encryption_enabled", "rds_instance_storage_encrypted", "s3_bucket_default_encryption", "s3_bucket_secure_transport_policy", "sagemaker_notebook_instance_encryption_enabled", "sns_topics_kms_encryption_at_rest_enabled"},
}
var Nist_2_3_14_1 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_14_1",
	Name:          "3.14.1 Identify, report, and correct system flaws in a timely manner",
	Description:   "Organizations identify systems that are affected by announced software and firmware flaws including potential vulnerabilities resulting from those flaws and report this information to designated personnel with information security responsibilities. Security-relevant updates include patches, service packs, hot fixes, and anti-virus signatures. Organizations address flaws discovered during security assessments, continuous monitoring, incident response activities, and system error handling. Organizations can take advantage of available resources such as the Common Weakness Enumeration (CWE) database or Common Vulnerabilities and Exposures (CVE) database in remediating flaws discovered in organizational systems. Organization-defined time periods for updating security-relevant software and firmware may vary based on a variety of factors including the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). Some types of flaw remediation may require more testing than other types of remediation.",
	Section:       "3.14 System and Information integrity",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled"},
}
var Nist_2_3_14_2 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_14_2",
	Name:          "3.14.2 Provide protection from malicious code at designated locations within organizational systems",
	Description:   "Designated locations include system entry and exit points which may include firewalls, remoteaccess servers, workstations, electronic mail servers, web servers, proxy servers, notebook computers, and mobile devices. Malicious code includes viruses, worms, Trojan horses, and spyware. Malicious code can be encoded in various formats (e.g., UUENCODE, Unicode), contained within compressed or hidden files, or hidden in files using techniques such as steganography. Malicious code can be inserted into systems in a variety of ways including web accesses, electronic mail, electronic mail attachments, and portable storage devices. Malicious code insertions occur through the exploitation of system vulnerabilities. Malicious code protection mechanisms include anti-virus signature definitions and reputationbased technologies. A variety of technologies and methods exist to limit or eliminate the effects of malicious code. Pervasive configuration management and comprehensive software integrity controls may be effective in preventing execution of unauthorized code. In addition to commercial off-the-shelf software, malicious code may also be present in custom-built software. This could include logic bombs, back doors, and other types of cyber-attacks that could affect organizational missions/business functions. Traditional malicious code protection mechanisms cannot always detect such code. In these situations, organizations rely instead on other safeguards including secure coding practices, configuration management and control, trusted procurement processes, and monitoring practices to help ensure that software does not perform functions other than the functions intended.",
	Section:       "3.14 System and Information integrity",
	Checks:        []string{"ec2_instance_managed_by_ssm", "guardduty_is_enabled", "securityhub_enabled", "ssm_managed_compliant_patching", "ssm_managed_compliant_patching"},
}
var Nist_2_3_14_3 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_14_3",
	Name:          "3.14.3 Monitor system security alerts and advisories and take action in response",
	Description:   "There are many publicly available sources of system security alerts and advisories. For example, the Department of Homeland Security’s Cybersecurity and Infrastructure Security Agency (CISA) generates security alerts and advisories to maintain situational awareness across the federal government and in nonfederal organizations. Software vendors, subscription services, and industry information sharing and analysis centers (ISACs) may also provide security alerts and advisories. Examples of response actions include notifying relevant external organizations, for example, external mission/business partners, supply chain partners, external service providers, and peer or supporting organizations.",
	Section:       "3.14 System and Information integrity",
	Checks:        []string{"guardduty_is_enabled", "securityhub_enabled", "ssm_managed_compliant_patching"},
}
var Nist_2_3_14_4 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_14_4",
	Name:          "3.14.4 Update malicious code protection mechanisms when new releases are available",
	Description:   "Malicious code protection mechanisms include anti-virus signature definitions and reputationbased technologies. A variety of technologies and methods exist to limit or eliminate the effects of malicious code. Pervasive configuration management and comprehensive software integrity controls may be effective in preventing execution of unauthorized code. In addition to commercial off-the-shelf software, malicious code may also be present in custom-built software. This could include logic bombs, back doors, and other types of cyber-attacks that could affect organizational missions/business functions. Traditional malicious code protection mechanisms cannot always detect such code. In these situations, organizations rely instead on other safeguards including secure coding practices, configuration management and control, trusted procurement processes, and monitoring practices to help ensure that software does not perform functions other than the functions intended.",
	Section:       "3.14 System and Information integrity",
	Checks:        []string{"guardduty_is_enabled"},
}
var Nist_2_3_14_6 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_14_6",
	Name:          "3.14.6 Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks",
	Description:   "System monitoring includes external and internal monitoring. External monitoring includes the observation of events occurring at the system boundary (i.e., part of perimeter defense and boundary protection). Internal monitoring includes the observation of events occurring within the system. Organizations can monitor systems, for example, by observing audit record activities in real time or by observing other system aspects such as access patterns, characteristics of access, and other actions. The monitoring objectives may guide determination of the events. System monitoring capability is achieved through a variety of tools and techniques (e.g., intrusion detection systems, intrusion prevention systems, malicious code protection software, scanning tools, audit record monitoring software, network monitoring software). Strategic locations for monitoring devices include selected perimeter locations and near server farms supporting critical applications, with such devices being employed at managed system interfaces. The granularity of monitoring information collected is based on organizational monitoring objectives and the capability of systems to support such objectives. System monitoring is an integral part of continuous monitoring and incident response programs. Output from system monitoring serves as input to continuous monitoring and incident response programs. A network connection is any connection with a device that communicates through a network (e.g., local area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet). Local, network, and remote connections can be either wired or wireless. Unusual or unauthorized activities or conditions related to inbound/outbound communications traffic include internal traffic that indicates the presence of malicious code in systems or propagating among system components, the unauthorized exporting of information, or signaling to external systems. Evidence of malicious code is used to identify potentially compromised systems or system components. System monitoring requirements, including the need for specific types of system monitoring, may be referenced in other requirements.",
	Section:       "3.14 System and Information integrity",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "guardduty_is_enabled", "rds_instance_integration_cloudwatch_logs", "s3_bucket_server_access_logging_enabled", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
var Nist_2_3_14_7 = &NistComp{
	Framework:     "NIST-800-171-Revision-2",
	Provider:      "AWS",
	Frameworkdesc: "The cybersecurity controls within NIST 800-171 safeguard CUI in the IT networks of government contractors and subcontractors. It defines the practices and procedures that government contractors must adhere to when their networks process or store CUI. NIST 800-171 only applies to those parts of a contractor’s network where CUI is present.",
	Id:            "3_14_7",
	Name:          "3.14.7 Identify unauthorized use of organizational systems",
	Description:   "System monitoring includes external and internal monitoring. System monitoring can detect unauthorized use of organizational systems. System monitoring is an integral part of continuous monitoring and incident response programs. Monitoring is achieved through a variety of tools and techniques (e.g., intrusion detection systems, intrusion prevention systems, malicious code protection software, scanning tools, audit record monitoring software, network monitoring software). Output from system monitoring serves as input to continuous monitoring and incident response programs. Unusual/unauthorized activities or conditions related to inbound and outbound communications traffic include internal traffic that indicates the presence of malicious code in systems or propagating among system components, the unauthorized exporting of information, or signaling to external systems. Evidence of malicious code is used to identify potentially compromised systems or system components. System monitoring requirements, including the need for specific types of system monitoring, may be referenced in other requirements.",
	Section:       "3.14 System and Information integrity",
	Checks:        []string{"apigateway_restapi_logging_enabled", "cloudtrail_multi_region_enabled", "cloudtrail_s3_dataevents_read_enabled", "cloudtrail_s3_dataevents_write_enabled", "cloudtrail_multi_region_enabled", "elbv2_logging_enabled", "elb_logging_enabled", "guardduty_is_enabled", "rds_instance_integration_cloudwatch_logs", "s3_bucket_server_access_logging_enabled", "securityhub_enabled", "vpc_flow_logs_enabled"},
}
