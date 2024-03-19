package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type CFramework struct {
	Framework    string  `json:"Framework"`
	Version      string  `json:"Version"`
	Provider     string  `json:"Provider"`
	Description  string  `json:"Description"`
	Requirements []check `json:"Requirements"`
}

type check struct {
	Id          string `json:"Id"`
	Name        string `json:"Name"`
	Description string `json:"Description"`
	Attributes  []struct {
		ItemId     string `json:"ItemId"`
		Section    string `json:"Section"`
		SubSection string `json:"SubSection"`
		Service    string `json:"Service"`
		Type       string `json:Type`
	} `json:"Attributes"`
	Checks []string `json:"Checks"`
}

func main() {
	// JSON data
	jsonData := `{
		"Framework": "SOC2",
		"Version": "",
		"Provider": "AWS",
		"Description": "System and Organization Controls (SOC), defined by the American Institute of Certified Public Accountants (AICPA), is the name of a set of reports that's produced during an audit. It's intended for use by service organizations (organizations that provide information systems as a service to other organizations) to issue validated reports of internal controls over those information systems to the users of those services. The reports focus on controls grouped into five categories known as Trust Service Principles.",
		"Requirements": [
		  {
			"Id": "cc_1_1",
			"Name": "CC1.1 COSO Principle 1: The entity demonstrates a commitment to integrity and ethical values",
			"Description": "Sets the Tone at the Top - The board of directors and management, at all levels, demonstrate through their directives, actions, and behavior the importance of integrity and ethical values to support the functioning of the system of internal control. Establishes Standards of Conduct - The expectations of the board of directors and senior management concerning integrity and ethical values are defined in the entity’s standards of conduct and understood at all levels of the entity and by outsourced service providers and business partners. Evaluates Adherence to Standards of Conduct - Processes are in place to evaluate the performance of individuals and teams against the entity’s expected standards of conduct. Addresses Deviations in a Timely Manner - Deviations from the entity’s expected standards of conduct are identified and remedied in a timely and consistent manner.",
			"Attributes": [
			  {
				"ItemId": "cc_1_1",
				"Section": "CC1.0 - Common Criteria Related to Control Environment",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_1_2",
			"Name": "CC1.2 COSO Principle 2: The board of directors demonstrates independence from management and exercises oversight of the development and performance of internal control",
			"Description": "Establishes Oversight Responsibilities - The board of directors identifies and accepts its oversight responsibilities in relation to established requirements and expectations. Applies Relevant Expertise - The board of directors defines, maintains, and periodically evaluates the skills and expertise needed among its members to enable them to ask probing questions of senior management and take commensurate action. Operates Independently - The board of directors has sufficient members who are independent from management and objective in evaluations and decision making. Additional point of focus specifically related to all engagements using the trust services criteria: Supplements Board Expertise - The board of directors supplements its expertise relevant to security, availability, processing integrity, confidentiality, and privacy, as needed, through the use of a subcommittee or consultants.",
			"Attributes": [
			  {
				"ItemId": "cc_1_2",
				"Section": "CC1.0 - Common Criteria Related to Control Environment",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_1_3",
			"Name": "CC1.3 COSO Principle 3: Management establishes, with board oversight, structures, reporting lines, and appropriate authorities and responsibilities in the pursuit of objectives",
			"Description": "Considers All Structures of the Entity - Management and the board of directors consider the multiple structures used (including operating units, legal entities, geographic distribution, and outsourced service providers) to support the achievement of objectives. Establishes Reporting Lines - Management designs and evaluates lines of reporting for each entity structure to enable execution of authorities and responsibilities and flow of information to manage the activities of the entity. Defines, Assigns, and Limits Authorities and Responsibilities - Management and the board of directors delegate authority, define responsibilities, and use appropriate processes and technology to assign responsibility and segregate duties as necessary at the various levels of the organization. Additional points of focus specifically related to all engagements using the trust services criteria: Addresses Specific Requirements When Defining Authorities and Responsibilities—Management and the board of directors consider requirements relevant to security, availability, processing integrity, confidentiality, and privacy when defining authorities and responsibilities. Considers Interactions With External Parties When Establishing Structures, Reporting Lines, Authorities, and Responsibilities — Management and the board of directors consider the need for the entity to interact with and monitor the activities of external parties when establishing structures, reporting lines, authorities, and responsibilities.",
			"Attributes": [
			  {
				"ItemId": "cc_1_3",
				"Section": "CC1.0 - Common Criteria Related to Control Environment",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "iam_policy_attached_only_to_group_or_roles",
			  "iam_aws_attached_policy_no_administrative_privileges",
			  "iam_customer_attached_policy_no_administrative_privileges",
			  "iam_inline_policy_no_administrative_privileges",
			  "iam_user_accesskey_unused",
			  "iam_user_console_access_unused"
			]
		  },
		  {
			"Id": "cc_1_4",
			"Name": "CC1.4 COSO Principle 4: The entity demonstrates a commitment to attract, develop, and retain competent individuals in alignment with objectives",
			"Description": "Establishes Policies and Practices - Policies and practices reflect expectations of competence necessary to support the achievement of objectives. Evaluates Competence and Addresses Shortcomings - The board of directors and management evaluate competence across the entity and in outsourced service providers in relation to established policies and practices and act as necessary to address shortcomings. Attracts, Develops, and Retains Individuals - The entity provides the mentoring and training needed to attract, develop, and retain sufficient and competent personnel and outsourced service providers to support the achievement of objectives. Plans and Prepares for Succession - Senior management and the board of directors develop contingency plans for assignments of responsibility important for internal control. Additional point of focus specifically related to all engagements using the trust services criteria: Considers the Background of Individuals - The entity considers the background of potential and existing personnel, contractors, and vendor employees when determining whether to employ and retain the individuals. Considers the Technical Competency of Individuals - The entity considers the technical competency of potential and existing personnel, contractors, and vendor employees when determining whether to employ and retain the individuals. Provides Training to Maintain Technical Competencies - The entity provides training programs, including continuing education and training, to ensure skill sets and technical competency of existing personnel, contractors, and vendor employees are developed and maintained.",
			"Attributes": [
			  {
				"ItemId": "cc_1_4",
				"Section": "CC1.0 - Common Criteria Related to Control Environment",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_1_5",
			"Name": "CC1.5 COSO Principle 5: The entity holds individuals accountable for their internal control responsibilities in the pursuit of objectives",
			"Description": "Enforces Accountability Through Structures, Authorities, and Responsibilities - Management and the board of directors establish the mechanisms to communicate and hold individuals accountable for performance of internal control responsibilities across the entity and implement corrective action as necessary. Establishes Performance Measures, Incentives, and Rewards - Management and the board of directors establish performance measures, incentives, and other rewards appropriate for responsibilities at all levels of the entity, reflecting appropriate dimensions of performance and expected standards of conduct, and considering the achievement of both short-term and longer-term objectives. Evaluates Performance Measures, Incentives, and Rewards for Ongoing Relevance - Management and the board of directors align incentives and rewards with the fulfillment of internal control responsibilities in the achievement of objectives. Considers Excessive Pressures - Management and the board of directors evaluate and adjust pressures associated with the achievement of objectives as they assign responsibilities, develop performance measures, and evaluate performance. Evaluates Performance and Rewards or Disciplines Individuals - Management and the board of directors evaluate performance of internal control responsibilities, including adherence to standards of conduct and expected levels of competence, and provide rewards or exercise disciplinary action, as appropriate.",
			"Attributes": [
			  {
				"ItemId": "cc_1_5",
				"Section": "CC1.0 - Common Criteria Related to Control Environment",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_2_1",
			"Name": "CC2.1 COSO Principle 13: The entity obtains or generates and uses relevant, quality information to support the functioning of internal control",
			"Description": "Identifies Information Requirements - A process is in place to identify the information required and expected to support the functioning of the other components of internal control and the achievement of the entity’s objectives. Captures Internal and External Sources of Data - Information systems capture internal and external sources of data. Processes Relevant Data Into Information - Information systems process and transform relevant data into information. Maintains Quality Throughout Processing - Information systems produce information that is timely, current, accurate, complete, accessible, protected, verifiable, and retained. Information is reviewed to assess its relevance in supporting the internal control components.",
			"Attributes": [
			  {
				"ItemId": "cc_2_1",
				"Section": "CC2.0 - Common Criteria Related to Communication and Information",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "cloudtrail_s3_dataevents_read_enabled",
			  "cloudtrail_s3_dataevents_write_enabled",
			  "cloudtrail_multi_region_enabled",
			  "config_recorder_all_regions_enabled"
			]
		  },
		  {
			"Id": "cc_2_2",
			"Name": "CC2.2 COSO Principle 14: The entity internally communicates information, including objectives and responsibilities for internal control, necessary to support the functioning of internal control",
			"Description": "Communicates Internal Control Information - A process is in place to communicate required information to enable all personnel to understand and carry out their internal control responsibilities. Communicates With the Board of Directors - Communication exists between management and the board of directors so that both have information needed to fulfill their roles with respect to the entity’s objectives. Provides Separate Communication Lines - Separate communication channels, such as whistle-blower hotlines, are in place and serve as fail-safe mechanisms to enable anonymous or confidential communication when normal channels are inoperative or ineffective. Selects Relevant Method of Communication - The method of communication considers the timing, audience, and nature of the information. Additional point of focus specifically related to all engagements using the trust services criteria: Communicates Responsibilities - Entity personnel with responsibility for designing, developing, implementing,operating, maintaining, or monitoring system controls receive communications about their responsibilities, including changes in their responsibilities, and have the information necessary to carry out those responsibilities. Communicates Information on Reporting Failures, Incidents, Concerns, and Other Matters—Entity personnel are provided with information on how to report systems failures, incidents, concerns, and other complaints to personnel. Communicates Objectives and Changes to Objectives - The entity communicates its objectives and changes to those objectives to personnel in a timely manner. Communicates Information to Improve Security Knowledge and Awareness - The entity communicates information to improve security knowledge and awareness and to model appropriate security behaviors to personnel through a security awareness training program. Additional points of focus that apply only when an engagement using the trust services criteria is performed at the system level: Communicates Information About System Operation and Boundaries - The entity prepares and communicates information about the design and operation of the system and its boundaries to authorized personnel to enable them to understand their role in the system and the results of system operation. Communicates System Objectives - The entity communicates its objectives to personnel to enable them to carry out their responsibilities. Communicates System Changes - System changes that affect responsibilities or the achievement of the entity's objectives are communicated in a timely manner.",
			"Attributes": [
			  {
				"ItemId": "cc_2_2",
				"Section": "CC2.0 - Common Criteria Related to Communication and Information",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_2_3",
			"Name": "CC2.3 COSO Principle 15: The entity communicates with external parties regarding matters affecting the functioning of internal control",
			"Description": "Communicates to External Parties - Processes are in place to communicate relevant and timely information to external parties, including shareholders, partners, owners, regulators, customers, financial analysts, and other external parties. Enables Inbound Communications - Open communication channels allow input from customers, consumers, suppliers, external auditors, regulators, financial analysts, and others, providing management and the board of directors with relevant information. Communicates With the Board of Directors - Relevant information resulting from assessments conducted by external parties is communicated to the board of directors. Provides Separate Communication Lines - Separate communication channels, such as whistle-blower hotlines, are in place and serve as fail-safe mechanisms to enable anonymous or confidential communication when normal channels are inoperative or ineffective. Selects Relevant Method of Communication - The method of communication considers the timing, audience, and nature of the communication and legal, regulatory, and fiduciary requirements and expectations. Communicates Objectives Related to Confidentiality and Changes to Objectives - The entity communicates, to external users, vendors, business partners and others whose products and services are part of the system, objectives and changes to objectives related to confidentiality. Additional point of focus that applies only to an engagement using the trust services criteria for privacy: Communicates Objectives Related to Privacy and Changes to Objectives - The entity communicates, to external users, vendors, business partners and others whose products and services are part of the system, objectives related to privacy and changes to those objectives. Additional points of focus that apply only when an engagement using the trust services criteria is performed at the system level: Communicates Information About System Operation and Boundaries - The entity prepares and communicates information about the design and operation of the system and its boundaries to authorized external users to permit users to understand their role in the system and the results of system operation. Communicates System Objectives - The entity communicates its system objectives to appropriate external users. Communicates System Responsibilities - External users with responsibility for designing, developing, implementing, operating, maintaining, and monitoring system controls receive communications about their responsibilities and have the information necessary to carry out those responsibilities. Communicates Information on Reporting System Failures, Incidents, Concerns, and Other Matters - External users are provided with information on how to report systems failures, incidents, concerns, and other complaints to appropriate personnel.",
			"Attributes": [
			  {
				"ItemId": "cc_2_3",
				"Section": "CC2.0 - Common Criteria Related to Communication and Information",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_3_1",
			"Name": "CC3.1 COSO Principle 6: The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives",
			"Description": "Operations Objectives: Reflects Management's Choices - Operations objectives reflect management's choices about structure, industry considerations, and performance of the entity. Considers Tolerances for Risk - Management considers the acceptable levels of variation relative to the achievement of operations objectives. External Financial Reporting Objectives: Complies With Applicable Accounting Standards - Financial reporting objectives are consistent with accounting principles suitable and available for that entity. The accounting principles selected are appropriate in the circumstances. External Nonfinancial Reporting Objectives: Complies With Externally Established Frameworks - Management establishes objectives consistent with laws and regulations or standards and frameworks of recognized external organizations. Reflects Entity Activities - External reporting reflects the underlying transactions and events within a range of acceptable limits. Considers the Required Level of Precision—Management reflects the required level of precision and accuracy suitable for user needs and based on criteria established by third parties in nonfinancial reporting. Internal Reporting Objectives: Reflects Management's Choices - Internal reporting provides management with accurate and complete information regarding management's choices and information needed in managing the entity. Considers the Required Level of Precision—Management reflects the required level of precision and accuracy suitable for user needs in nonfinancial reporting objectives and materiality within financial reporting objectives. Reflects Entity Activities—Internal reporting reflects the underlying transactions and events within a range of acceptable limits. Compliance Objectives: Reflects External Laws and Regulations - Laws and regulations establish minimum standards of conduct, which the entity integrates into compliance objectives. Considers Tolerances for Risk - Management considers the acceptable levels of variation relative to the achievement of operations objectives. Additional point of focus specifically related to all engagements using the trust services criteria: Establishes Sub-objectives to Support Objectives—Management identifies sub-objectives related to security, availability, processing integrity, confidentiality, and privacy to support the achievement of the entity’s objectives related to reporting, operations, and compliance.",
			"Attributes": [
			  {
				"ItemId": "cc_3_1",
				"Section": "CC3.0 - Common Criteria Related to Risk Assessment",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "guardduty_is_enabled",
			  "securityhub_enabled",
			  "config_recorder_all_regions_enabled"
			]
		  },
		  {
			"Id": "cc_3_2",
			"Name": "CC3.2 COSO Principle 7: The entity identifies risks to the achievement of its objectives across the entity and analyzes risks as a basis for determining how the risks should be managed",
			"Description": "Includes Entity, Subsidiary, Division, Operating Unit, and Functional Levels - The entity identifies and assesses risk at the entity, subsidiary, division, operating unit, and functional levels relevant to the achievement of objectives. Analyzes Internal and External Factors - Risk identification considers both internal and external factors and their impact on the achievement of objectives. Involves Appropriate Levels of Management - The entity puts into place effective risk assessment mechanisms that involve appropriate levels of management. Estimates Significance of Risks Identified - Identified risks are analyzed through a process that includes estimating the potential significance of the risk. Determines How to Respond to Risks - Risk assessment includes considering how the risk should be managed and whether to accept, avoid, reduce, or share the risk. Additional points of focus specifically related to all engagements using the trust services criteria: Identifies and Assesses Criticality of Information Assets and Identifies Threats and Vulnerabilities - The entity's risk identification and assessment process includes (1) identifying information assets, including physical devices and systems, virtual devices, software, data and data flows, external information systems, and organizational roles; (2) assessing the criticality of those information assets; (3) identifying the threats to the assets from intentional (including malicious) and unintentional acts and environmental events; and (4) identifying the vulnerabilities of the identified assets.",
			"Attributes": [
			  {
				"ItemId": "cc_3_2",
				"Section": "CC3.0 - Common Criteria Related to Risk Assessment",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "ec2_instance_managed_by_ssm",
			  "ssm_managed_compliant_patching",
			  "guardduty_no_high_severity_findings",
			  "guardduty_is_enabled",
			  "ssm_managed_compliant_patching"
			]
		  },
		  {
			"Id": "cc_3_3",
			"Name": "CC3.3 COSO Principle 8: The entity considers the potential for fraud in assessing risks to the achievement of objectives",
			"Description": "Considers Various Types of Fraud - The assessment of fraud considers fraudulent reporting, possible loss of assets, and corruption resulting from the various ways that fraud and misconduct can occur. Assesses Incentives and Pressures - The assessment of fraud risks considers incentives and pressures. Assesses Opportunities - The assessment of fraud risk considers opportunities for unauthorized acquisition,use, or disposal of assets, altering the entity’s reporting records, or committing other inappropriate acts. Assesses Attitudes and Rationalizations - The assessment of fraud risk considers how management and other personnel might engage in or justify inappropriate actions. Additional point of focus specifically related to all engagements using the trust services criteria: Considers the Risks Related to the Use of IT and Access to Information - The assessment of fraud risks includes consideration of threats and vulnerabilities that arise specifically from the use of IT and access to information.",
			"Attributes": [
			  {
				"ItemId": "cc_3_3",
				"Section": "CC3.0 - Common Criteria Related to Risk Assessment",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_3_4",
			"Name": "CC3.4 COSO Principle 9: The entity identifies and assesses changes that could significantly impact the system of internal control",
			"Description": "Assesses Changes in the External Environment - The risk identification process considers changes to the regulatory, economic, and physical environment in which the entity operates. Assesses Changes in the Business Model - The entity considers the potential impacts of new business lines, dramatically altered compositions of existing business lines, acquired or divested business operations on the system of internal control, rapid growth, changing reliance on foreign geographies, and new technologies. Assesses Changes in Leadership - The entity considers changes in management and respective attitudes and philosophies on the system of internal control. Assess Changes in Systems and Technology - The risk identification process considers changes arising from changes in the entity’s systems and changes in the technology environment. Assess Changes in Vendor and Business Partner Relationships - The risk identification process considers changes in vendor and business partner relationships.",
			"Attributes": [
			  {
				"ItemId": "cc_3_4",
				"Section": "CC3.0 - Common Criteria Related to Risk Assessment",
				"Service": "config",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "config_recorder_all_regions_enabled"
			]
		  },
		  {
			"Id": "cc_4_1",
			"Name": "CC4.1 COSO Principle 16: The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning",
			"Description": "Considers a Mix of Ongoing and Separate Evaluations - Management includes a balance of ongoing and separate evaluations. Considers Rate of Change - Management considers the rate of change in business and business processes when selecting and developing ongoing and separate evaluations. Establishes Baseline Understanding - The design and current state of an internal control system are used to establish a baseline for ongoing and separate evaluations. Uses Knowledgeable Personnel - Evaluators performing ongoing and separate evaluations have sufficient knowledge to understand what is being evaluated. Integrates With Business Processes - Ongoing evaluations are built into the business processes and adjust to changing conditions. Adjusts Scope and Frequency—Management varies the scope and frequency of separate evaluations depending on risk. Objectively Evaluates - Separate evaluations are performed periodically to provide objective feedback. Considers Different Types of Ongoing and Separate Evaluations - Management uses a variety of different types of ongoing and separate evaluations, including penetration testing, independent certification made against established specifications (for example, ISO certifications), and internal audit assessments.",
			"Attributes": [
			  {
				"ItemId": "cc_4_1",
				"Section": "CC4.0 - Monitoring Activities",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_4_2",
			"Name": "CC4.2 COSO Principle 17: The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action, including senior management and the board of directors, as appropriate",
			"Description": "Assesses Results - Management and the board of directors, as appropriate, assess results of ongoing and separate evaluations. Communicates Deficiencies - Deficiencies are communicated to parties responsible for taking corrective action and to senior management and the board of directors, as appropriate. Monitors Corrective Action - Management tracks whether deficiencies are remedied on a timely basis.",
			"Attributes": [
			  {
				"ItemId": "cc_4_2",
				"Section": "CC4.0 - Monitoring Activities",
				"Service": "guardduty",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "guardduty_is_enabled",
			  "guardduty_no_high_severity_findings"
			]
		  },
		  {
			"Id": "cc_5_1",
			"Name": "CC5.1 COSO Principle 10: The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels",
			"Description": "Integrates With Risk Assessment - Control activities help ensure that risk responses that address and mitigate risks are carried out. Considers Entity-Specific Factors - Management considers how the environment, complexity, nature, and scope of its operations, as well as the specific characteristics of its organization, affect the selection and development of control activities. Determines Relevant Business Processes - Management determines which relevant business processes require control activities. Evaluates a Mix of 2017 Data Submitted Types - Control activities include a range and variety of controls and may include a balance of approaches to mitigate risks, considering both manual and automated controls, and preventive and detective controls. Considers at What Level Activities Are Applied - Management considers control activities at various levels in the entity. Addresses Segregation of Duties - Management segregates incompatible duties, and where such segregation is not practical, management selects and develops alternative control activities.",
			"Attributes": [
			  {
				"ItemId": "cc_5_1",
				"Section": "CC5.0 - Control Activities",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_5_2",
			"Name": "CC5.2 COSO Principle 11: The entity also selects and develops general control activities over technology to support the achievement of objectives",
			"Description": "Determines Dependency Between the Use of Technology in Business Processes and Technology General Controls - Management understands and determines the dependency and linkage between business processes, automated control activities, and technology general controls. Establishes Relevant Technology Infrastructure Control Activities - Management selects and develops control activities over the technology infrastructure, which are designed and implemented to help ensure the completeness, accuracy, and availability of technology processing. Establishes Relevant Security Management Process Controls Activities - Management selects and develops control activities that are designed and implemented to restrict technology access rights to authorized users commensurate with their job responsibilities and to protect the entity’s assets from external threats. Establishes Relevant Technology Acquisition, Development, and Maintenance Process Control Activities - Management selects and develops control activities over the acquisition, development, and maintenance of technology and its infrastructure to achieve management’s objectives.",
			"Attributes": [
			  {
				"ItemId": "cc_5_2",
				"Section": "CC5.0 - Control Activities",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_5_3",
			"Name": "CCC5.3 COSO Principle 12: The entity deploys control activities through policies that establish what is expected and in procedures that put policies into action",
			"Description": "Establishes Policies and Procedures to Support Deployment of Management ‘s Directives - Management establishes control activities that are built into business processes and employees’ day-to-day activities through policies establishing what is expected and relevant procedures specifying actions. Establishes Responsibility and Accountability for Executing Policies and Procedures - Management establishes responsibility and accountability for control activities with management (or other designated personnel) of the business unit or function in which the relevant risks reside. Performs in a Timely Manner - Responsible personnel perform control activities in a timely manner as defined by the policies and procedures. Takes Corrective Action - Responsible personnel investigate and act on matters identified as a result of executing control activities. Performs Using Competent Personnel - Competent personnel with sufficient authority perform control activities with diligence and continuing focus. Reassesses Policies and Procedures - Management periodically reviews control activities to determine their continued relevance and refreshes them when necessary.",
			"Attributes": [
			  {
				"ItemId": "cc_5_3",
				"Section": "CC5.0 - Control Activities",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_6_1",
			"Name": "CC6.1 The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives",
			"Description": "Identifies and Manages the Inventory of Information Assets - The entity identifies, inventories, classifies, and manages information assets. Restricts Logical Access - Logical access to information assets, including hardware, data (at-rest, during processing, or in transmission), software, administrative authorities, mobile devices, output, and offline system components is restricted through the use of access control software and rule sets. Identifies and Authenticates Users - Persons, infrastructure and software are identified and authenticated prior to accessing information assets, whether locally or remotely. Considers Network Segmentation - Network segmentation permits unrelated portions of the entity's information system to be isolated from each other. Manages Points of Access - Points of access by outside entities and the types of data that flow through the points of access are identified, inventoried, and managed. The types of individuals and systems using each point of access are identified, documented, and managed. Restricts Access to Information Assets - Combinations of data classification, separate data structures, port restrictions, access protocol restrictions, user identification, and digital certificates are used to establish access control rules for information assets. Manages Identification and Authentication - Identification and authentication requirements are established, documented, and managed for individuals and systems accessing entity information, infrastructure and software. Manages Credentials for Infrastructure and Software - New internal and external infrastructure and software are registered, authorized, and documented prior to being granted access credentials and implemented on the network or access point. Credentials are removed and access is disabled when access is no longer required or the infrastructure and software are no longer in use. Uses Encryption to Protect Data - The entity uses encryption to supplement other measures used to protect data-at-rest, when such protections are deemed appropriate based on assessed risk. Protects Encryption Keys - Processes are in place to protect encryption keys during generation, storage, use, and destruction.",
			"Attributes": [
			  {
				"ItemId": "cc_6_1",
				"Section": "CC6.0 - Logical and Physical Access",
				"Service": "s3",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "s3_bucket_public_access"
			]
		  },
		  {
			"Id": "cc_6_2",
			"Name": "CC6.2 Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity",
			"Description": "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity. For those users whose access is administered by the entity, user system credentials are removed when user access is no longer authorized. Controls Access Credentials to Protected Assets - Information asset access credentials are created based on an authorization from the system's asset owner or authorized custodian. Removes Access to Protected Assets When Appropriate - Processes are in place to remove credential access when an individual no longer requires such access. Reviews Appropriateness of Access Credentials - The appropriateness of access credentials is reviewed on a periodic basis for unnecessary and inappropriate individuals with credentials.",
			"Attributes": [
			  {
				"ItemId": "cc_6_2",
				"Section": "CC6.0 - Logical and Physical Access",
				"Service": "rds",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "rds_instance_no_public_access"
			]
		  },
		  {
			"Id": "cc_6_3",
			"Name": "CC6.3 The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design and changes, giving consideration to the concepts of least privilege and segregation of duties, to meet the entity’s objectives",
			"Description": "Creates or Modifies Access to Protected Information Assets - Processes are in place to create or modify access to protected information assets based on authorization from the asset’s owner. Removes Access to Protected Information Assets - Processes are in place to remove access to protected information assets when an individual no longer requires access. Uses Role-Based Access Controls - Role-based access control is utilized to support segregation of incompatible functions.",
			"Attributes": [
			  {
				"ItemId": "cc_6_3",
				"Section": "CC6.0 - Logical and Physical Access",
				"Service": "iam",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "iam_aws_attached_policy_no_administrative_privileges",
			  "iam_customer_attached_policy_no_administrative_privileges",
			  "iam_inline_policy_no_administrative_privileges"
			]
		  },
		  {
			"Id": "cc_6_4",
			"Name": "CC6.4 The entity restricts physical access to facilities and protected information assets to authorized personnel to meet the entity’s objectives",
			"Description": "Creates or Modifies Physical Access - Processes are in place to create or modify physical access to facilities such as data centers, office spaces, and work areas, based on authorization from the system's asset owner. Removes Physical Access - Processes are in place to remove access to physical resources when an individual no longer requires access. Reviews Physical Access - Processes are in place to periodically review physical access to ensure consistency with job responsibilities.",
			"Attributes": [
			  {
				"ItemId": "cc_6_4",
				"Section": "CC6.0 - Logical and Physical Access",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_6_5",
			"Name": "CC6.5 The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished and is no longer required to meet the entity’s objectives",
			"Description": "Identifies Data and Software for Disposal - Procedures are in place to identify data and software stored on equipment to be disposed and to render such data and software unreadable. Removes Data and Software From Entity Control - Procedures are in place to remove data and software stored on equipment to be removed from the physical control of the entity and to render such data and software unreadable.",
			"Attributes": [
			  {
				"ItemId": "cc_6_5",
				"Section": "CC6.0 - Logical and Physical Access",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_6_6",
			"Name": "CC6.6 The entity implements logical access security measures to protect against threats from sources outside its system boundaries",
			"Description": "Restricts Access — The types of activities that can occur through a communication channel (for example, FTP site, router port) are restricted. Protects Identification and Authentication Credentials — Identification and authentication credentials are protected during transmission outside its system boundaries. Requires Additional Authentication or Credentials — Additional authentication information or credentials are required when accessing the system from outside its boundaries. Implements Boundary Protection Systems — Boundary protection systems (for example, firewalls, demilitarized zones, and intrusion detection systems) are implemented to protect external access points from attempts and unauthorized access and are monitored to detect such attempts.",
			"Attributes": [
			  {
				"ItemId": "cc_6_6",
				"Section": "CC6.0 - Logical and Physical Access",
				"Service": "ec2",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "ec2_instance_public_ip"
			]
		  },
		  {
			"Id": "cc_6_7",
			"Name": "CC6.7 The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal to meet the entity’s objectives",
			"Description": "Restricts the Ability to Perform Transmission - Data loss prevention processes and technologies are used to restrict ability to authorize and execute transmission, movement and removal of information. Uses Encryption Technologies or Secure Communication Channels to Protect Data - Encryption technologies or secured communication channels are used to protect transmission of data and other communications beyond connectivity access points. Protects Removal Media - Encryption technologies and physical asset protections are used for removable media (such as USB drives and back-up tapes), as appropriate. Protects Mobile Devices - Processes are in place to protect mobile devices (such as laptops, smart phones and tablets) that serve as information assets.",
			"Attributes": [
			  {
				"ItemId": "cc_6_7",
				"Section": "CC6.0 - Logical and Physical Access",
				"Service": "acm",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "acm_certificates_expiration_check"
			]
		  },
		  {
			"Id": "cc_6_8",
			"Name": "CC6.8 The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software to meet the entity’s objectives",
			"Description": "Restricts Application and Software Installation - The ability to install applications and software is restricted to authorized individuals. Detects Unauthorized Changes to Software and Configuration Parameters - Processes are in place to detect changes to software and configuration parameters that may be indicative of unauthorized or malicious software. Uses a Defined Change Control Process - A management-defined change control process is used for the implementation of software. Uses Antivirus and Anti-Malware Software - Antivirus and anti-malware software is implemented and maintained to provide for the interception or detection and remediation of malware. Scans Information Assets from Outside the Entity for Malware and Other Unauthorized Software - Procedures are in place to scan information assets that have been transferred or returned to the entity’s custody for malware and other unauthorized software and to remove any items detected prior to its implementation on the network.",
			"Attributes": [
			  {
				"ItemId": "cc_6_8",
				"Section": "CC6.0 - Logical and Physical Access",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "guardduty_is_enabled",
			  "securityhub_enabled"
			]
		  },
		  {
			"Id": "cc_7_1",
			"Name": "CC7.1 To meet its objectives, the entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities",
			"Description": "Uses Defined Configuration Standards - Management has defined configuration standards. Monitors Infrastructure and Software - The entity monitors infrastructure and software for noncompliance with the standards, which could threaten the achievement of the entity's objectives. Implements Change-Detection Mechanisms - The IT system includes a change-detection mechanism (for example, file integrity monitoring tools) to alert personnel to unauthorized modifications of critical system files, configuration files, or content files. Detects Unknown or Unauthorized Components - Procedures are in place to detect the introduction of unknown or unauthorized components. Conducts Vulnerability Scans - The entity conducts vulnerability scans designed to identify potential vulnerabilities or misconfigurations on a periodic basis and after any significant change in the environment and takes action to remediate identified deficiencies on a timely basis.",
			"Attributes": [
			  {
				"ItemId": "cc_7_1",
				"Section": "CC7.0 - System Operations",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "guardduty_is_enabled",
			  "securityhub_enabled",
			  "ec2_instance_managed_by_ssm",
			  "ssm_managed_compliant_patching"
			]
		  },
		  {
			"Id": "cc_7_2",
			"Name": "CC7.2 The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events",
			"Description": "Implements Detection Policies, Procedures, and Tools - Detection policies and procedures are defined and implemented, and detection tools are implemented on Infrastructure and software to identify anomalies in the operation or unusual activity on systems. Procedures may include (1) a defined governance process for security event detection and management that includes provision of resources; (2) use of intelligence sources to identify newly discovered threats and vulnerabilities; and (3) logging of unusual system activities. Designs Detection Measures - Detection measures are designed to identify anomalies that could result from actual or attempted (1) compromise of physical barriers; (2) unauthorized actions of authorized personnel; (3) use of compromised identification and authentication credentials; (4) unauthorized access from outside the system boundaries; (5) compromise of authorized external parties; and (6) implementation or connection of unauthorized hardware and software. Implements Filters to Analyze Anomalies - Management has implemented procedures to filter, summarize, and analyze anomalies to identify security events. Monitors Detection Tools for Effective Operation - Management has implemented processes to monitor the effectiveness of detection tools.",
			"Attributes": [
			  {
				"ItemId": "cc_7_2",
				"Section": "CC7.0 - System Operations",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "cloudtrail_cloudwatch_logging_enabled",
			  "cloudwatch_changes_to_network_acls_alarm_configured",
			  "cloudwatch_changes_to_network_gateways_alarm_configured",
			  "cloudwatch_changes_to_network_route_tables_alarm_configured",
			  "cloudwatch_changes_to_vpcs_alarm_configured",
			  "cloudtrail_s3_dataevents_read_enabled",
			  "cloudtrail_s3_dataevents_write_enabled",
			  "elbv2_logging_enabled",
			  "elb_logging_enabled",
			  "s3_bucket_server_access_logging_enabled",
			  "rds_instance_integration_cloudwatch_logs",
			  "cloudtrail_multi_region_enabled",
			  "securityhub_enabled",
			  "cloudwatch_log_group_retention_policy_specific_days_enabled",
			  "cloudtrail_multi_region_enabled",
			  "redshift_cluster_audit_logging",
			  "vpc_flow_logs_enabled",
			  "ec2_instance_imdsv2_enabled",
			  "guardduty_is_enabled",
			  "apigateway_restapi_logging_enabled",
			  "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
			]
		  },
		  {
			"Id": "cc_7_3",
			"Name": "CC7.3 The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures",
			"Description": "Responds to Security Incidents - Procedures are in place for responding to security incidents and evaluating the effectiveness of those policies and procedures on a periodic basis. Communicates and Reviews Detected Security Events - Detected security events are communicated to and reviewed by the individuals responsible for the management of the security program and actions are taken, if necessary. Develops and Implements Procedures to Analyze Security Incidents - Procedures are in place to analyze security incidents and determine system impact. Assesses the Impact on Personal Information - Detected security events are evaluated to determine whether they could or did result in the unauthorized disclosure or use of personal information and whether there has been a failure to comply with applicable laws or regulations. Determines Personal Information Used or Disclosed - When an unauthorized use or disclosure of personal information has occurred, the affected information is identified.",
			"Attributes": [
			  {
				"ItemId": "cc_7_3",
				"Section": "CC7.0 - System Operations",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "cloudwatch_log_group_kms_encryption_enabled",
			  "cloudtrail_log_file_validation_enabled",
			  "cloudtrail_cloudwatch_logging_enabled",
			  "guardduty_is_enabled",
			  "apigateway_restapi_logging_enabled",
			  "rds_instance_integration_cloudwatch_logs",
			  "securityhub_enabled",
			  "cloudwatch_changes_to_network_acls_alarm_configured",
			  "cloudwatch_changes_to_network_gateways_alarm_configured",
			  "cloudwatch_changes_to_network_route_tables_alarm_configured",
			  "cloudwatch_changes_to_vpcs_alarm_configured",
			  "elbv2_logging_enabled",
			  "elb_logging_enabled",
			  "s3_bucket_server_access_logging_enabled",
			  "cloudwatch_log_group_retention_policy_specific_days_enabled",
			  "vpc_flow_logs_enabled",
			  "guardduty_no_high_severity_findings"
			]
		  },
		  {
			"Id": "cc_7_4",
			"Name": "CC7.4 The entity responds to identified security incidents by executing a defined incident response program to understand, contain, remediate, and communicate security incidents, as appropriate",
			"Description": "Assigns Roles and Responsibilities - Roles and responsibilities for the design, implementation, maintenance, and execution of the incident response program are assigned, including the use of external resources when necessary. Contains Security Incidents - Procedures are in place to contain security incidents that actively threaten entity objectives. Mitigates Ongoing Security Incidents - Procedures are in place to mitigate the effects of ongoing security incidents. Ends Threats Posed by Security Incidents - Procedures are in place to end the threats posed by security incidents through closure of the vulnerability, removal of unauthorized access, and other remediation actions. Restores Operations - Procedures are in place to restore data and business operations to an interim state that permits the achievement of entity objectives. Develops and Implements Communication Protocols for Security Incidents - Protocols for communicating security incidents and actions taken to affected parties are developed and implemented to meet the entity's objectives. Obtains Understanding of Nature of Incident and Determines Containment Strategy - An understanding of the nature (for example, the method by which the incident occurred and the affected system resources) and severity of the security incident is obtained to determine the appropriate containment strategy, including (1) a determination of the appropriate response time frame, and (2) the determination and execution of the containment approach. Remediates Identified Vulnerabilities - Identified vulnerabilities are remediated through the development and execution of remediation activities. Communicates Remediation Activities - Remediation activities are documented and communicated in accordance with the incident response program. Evaluates the Effectiveness of Incident Response - The design of incident response activities is evaluated for effectiveness on a periodic basis. Periodically Evaluates Incidents - Periodically, management reviews incidents related to security, availability, processing integrity, confidentiality, and privacy and identifies the need for system changes based on incident patterns and root causes. Communicates Unauthorized Use and Disclosure - Events that resulted in unauthorized use or disclosure of personal information are communicated to the data subjects, legal and regulatory authorities, and others as required. Application of Sanctions - The conduct of individuals and organizations operating under the authority of the entity and involved in the unauthorized use or disclosure of personal information is evaluated and, if appropriate, sanctioned in accordance with entity policies and legal and regulatory requirements.",
			"Attributes": [
			  {
				"ItemId": "cc_7_4",
				"Section": "CC7.0 - System Operations",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "cloudwatch_changes_to_network_acls_alarm_configured",
			  "cloudwatch_changes_to_network_gateways_alarm_configured",
			  "cloudwatch_changes_to_network_route_tables_alarm_configured",
			  "cloudwatch_changes_to_vpcs_alarm_configured",
			  "dynamodb_tables_pitr_enabled",
			  "dynamodb_tables_pitr_enabled",
			  "efs_have_backup_enabled",
			  "efs_have_backup_enabled",
			  "guardduty_is_enabled",
			  "guardduty_no_high_severity_findings",
			  "rds_instance_backup_enabled",
			  "rds_instance_backup_enabled",
			  "rds_instance_backup_enabled",
			  "redshift_cluster_automated_snapshot",
			  "s3_bucket_object_versioning",
			  "securityhub_enabled"
			]
		  },
		  {
			"Id": "cc_7_5",
			"Name": "CC7.5 The entity identifies, develops, and implements activities to recover from identified security incidents",
			"Description": "Restores the Affected Environment - The activities restore the affected environment to functional operation by rebuilding systems, updating software, installing patches, and changing configurations, as needed. Communicates Information About the Event - Communications about the nature of the incident, recovery actions taken, and activities required for the prevention of future security events are made to management and others as appropriate (internal and external). Determines Root Cause of the Event - The root cause of the event is determined. Implements Changes to Prevent and Detect Recurrences - Additional architecture or changes to preventive and detective controls, or both, are implemented to prevent and detect recurrences on a timely basis. Improves Response and Recovery Procedures - Lessons learned are analyzed, and the incident response plan and recovery procedures are improved. Implements Incident Recovery Plan Testing - Incident recovery plan testing is performed on a periodic basis. The testing includes (1) development of testing scenarios based on threat likelihood and magnitude; (2) consideration of relevant system components from across the entity that can impair availability; (3) scenarios that consider the potential for the lack of availability of key personnel; and (4) revision of continuity plans and systems based on test results.",
			"Attributes": [
			  {
				"ItemId": "cc_7_5",
				"Section": "CC7.0 - System Operations",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_8_1",
			"Name": "CC8.1 The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives",
			"Description": "Manages Changes Throughout the System Lifecycle - A process for managing system changes throughout the lifecycle of the system and its components (infrastructure, data, software and procedures) is used to support system availability and processing integrity. Authorizes Changes - A process is in place to authorize system changes prior to development. Designs and Develops Changes - A process is in place to design and develop system changes. Documents Changes - A process is in place to document system changes to support ongoing maintenance of the system and to support system users in performing their responsibilities. Tracks System Changes - A process is in place to track system changes prior to implementation. Configures Software - A process is in place to select and implement the configuration parameters used to control the functionality of software. Tests System Changes - A process is in place to test system changes prior to implementation. Approves System Changes - A process is in place to approve system changes prior to implementation. Deploys System Changes - A process is in place to implement system changes. Identifies and Evaluates System Changes - Objectives affected by system changes are identified, and the ability of the modified system to meet the objectives is evaluated throughout the system development life cycle. Identifies Changes in Infrastructure, Data, Software, and Procedures Required to Remediate Incidents - Changes in infrastructure, data, software, and procedures required to remediate incidents to continue to meet objectives are identified, and the change process is initiated upon identification. Creates Baseline Configuration of IT Technology - A baseline configuration of IT and control systems is created and maintained. Provides for Changes Necessary in Emergency Situations - A process is in place for authorizing, designing, testing, approving and implementing changes necessary in emergency situations (that is, changes that need to be implemented in an urgent timeframe). Protects Confidential Information - The entity protects confidential information during system design, development, testing, implementation, and change processes to meet the entity’s objectives related to confidentiality. Protects Personal Information - The entity protects personal information during system design, development, testing, implementation, and change processes to meet the entity’s objectives related to privacy.",
			"Attributes": [
			  {
				"ItemId": "cc_8_1",
				"Section": "CC8.0 - Change Management",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "config_recorder_all_regions_enabled"
			]
		  },
		  {
			"Id": "cc_9_1",
			"Name": "CC9.1 The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions",
			"Description": "Considers Mitigation of Risks of Business Disruption - Risk mitigation activities include the development of planned policies, procedures, communications, and alternative processing solutions to respond to, mitigate, and recover from security events that disrupt business operations. Those policies and procedures include monitoring processes and information and communications to meet the entity's objectives during response, mitigation, and recovery efforts. Considers the Use of Insurance to Mitigate Financial Impact Risks - The risk management activities consider the use of insurance to offset the financial impact of loss events that would otherwise impair the ability of the entity to meet its objectives.",
			"Attributes": [
			  {
				"ItemId": "cc_9_1",
				"Section": "CC9.0 - Risk Mitigation",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_9_2",
			"Name": "CC9.2 The entity assesses and manages risks associated with vendors and business partners",
			"Description": "Establishes Requirements for Vendor and Business Partner Engagements - The entity establishes specific requirements for a vendor and business partner engagement that includes (1) scope of services and product specifications, (2) roles and responsibilities, (3) compliance requirements, and (4) service levels. Assesses Vendor and Business Partner Risks - The entity assesses, on a periodic basis, the risks that vendors and business partners (and those entities’ vendors and business partners) represent to the achievement of the entity's objectives. Assigns Responsibility and Accountability for Managing Vendors and Business Partners - The entity assigns responsibility and accountability for the management of risks associated with vendors and business partners. Establishes Communication Protocols for Vendors and Business Partners - The entity establishes communication and resolution protocols for service or product issues related to vendors and business partners. Establishes Exception Handling Procedures From Vendors and Business Partners - The entity establishes exception handling procedures for service or product issues related to vendors and business partners. Assesses Vendor and Business Partner Performance - The entity periodically assesses the performance of vendors and business partners. Implements Procedures for Addressing Issues Identified During Vendor and Business Partner Assessments - The entity implements procedures for addressing issues identified with vendor and business partner relationships. Implements Procedures for Terminating Vendor and Business Partner Relationships - The entity implements procedures for terminating vendor and business partner relationships. Obtains Confidentiality Commitments from Vendors and Business Partners - The entity obtains confidentiality commitments that are consistent with the entity’s confidentiality commitments and requirements from vendors and business partners who have access to confidential information. Assesses Compliance With Confidentiality Commitments of Vendors and Business Partners - On a periodic and as-needed basis, the entity assesses compliance by vendors and business partners with the entity’s confidentiality commitments and requirements. Obtains Privacy Commitments from Vendors and Business Partners - The entity obtains privacy commitments, consistent with the entity’s privacy commitments and requirements, from vendors and business partners who have access to personal information. Assesses Compliance with Privacy Commitments of Vendors and Business Partners - On a periodic and as-needed basis, the entity assesses compliance by vendors and business partners with the entity’s privacy commitments and requirements and takes corrective action as necessary.",
			"Attributes": [
			  {
				"ItemId": "cc_9_2",
				"Section": "CC9.0 - Risk Mitigation",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_a_1_1",
			"Name": "A1.1 The entity maintains, monitors, and evaluates current processing capacity and use of system components (infrastructure, data, and software) to manage capacity demand and to enable the implementation of additional capacity to help meet its objectives",
			"Description": "Measures Current Usage - The use of the system components is measured to establish a baseline for capacity management and to use when evaluating the risk of impaired availability due to capacity constraints. Forecasts Capacity - The expected average and peak use of system components is forecasted and compared to system capacity and associated tolerances. Forecasting considers capacity in the event of the failure of system components that constrain capacity. Makes Changes Based on Forecasts - The system change management process is initiated when forecasted usage exceeds capacity tolerances.",
			"Attributes": [
			  {
				"ItemId": "cc_a_1_1",
				"Section": "CCA1.0 - Additional Criterial for Availability",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_a_1_2",
			"Name": "A1.2 The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data back-up processes, and recovery infrastructure to meet its objectives",
			"Description": "Measures Current Usage - The use of the system components is measured to establish a baseline for capacity management and to use when evaluating the risk of impaired availability due to capacity constraints. Forecasts Capacity - The expected average and peak use of system components is forecasted and compared to system capacity and associated tolerances. Forecasting considers capacity in the event of the failure of system components that constrain capacity. Makes Changes Based on Forecasts - The system change management process is initiated when forecasted usage exceeds capacity tolerances.",
			"Attributes": [
			  {
				"ItemId": "cc_a_1_2",
				"Section": "CCA1.0 - Additional Criterial for Availability",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "apigateway_restapi_logging_enabled",
			  "cloudtrail_multi_region_enabled",
			  "cloudtrail_multi_region_enabled",
			  "cloudtrail_cloudwatch_logging_enabled",
			  "dynamodb_tables_pitr_enabled",
			  "dynamodb_tables_pitr_enabled",
			  "efs_have_backup_enabled",
			  "efs_have_backup_enabled",
			  "elbv2_logging_enabled",
			  "elb_logging_enabled",
			  "rds_instance_backup_enabled",
			  "rds_instance_backup_enabled",
			  "rds_instance_integration_cloudwatch_logs",
			  "rds_instance_backup_enabled",
			  "redshift_cluster_automated_snapshot",
			  "s3_bucket_object_versioning"
			]
		  },
		  {
			"Id": "cc_a_1_3",
			"Name": "A1.3 The entity tests recovery plan procedures supporting system recovery to meet its objectives",
			"Description": "Implements Business Continuity Plan Testing - Business continuity plan testing is performed on a periodic basis. The testing includes (1) development of testing scenarios based on threat likelihood and magnitude; (2) consideration of system components from across the entity that can impair the availability; (3) scenarios that consider the potential for the lack of availability of key personnel; and (4) revision of continuity plans and systems based on test results. Tests Integrity and Completeness of Back-Up Data - The integrity and completeness of back-up information is tested on a periodic basis.",
			"Attributes": [
			  {
				"ItemId": "cc_a_1_3",
				"Section": "CCA1.0 - Additional Criterial for Availability",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "cc_c_1_1",
			"Name": "C1.1 The entity identifies and maintains confidential information to meet the entity’s objectives related to confidentiality",
			"Description": "Identifies Confidential information - Procedures are in place to identify and designate confidential information when it is received or created and to determine the period over which the confidential information is to be retained. Protects Confidential Information from Destruction - Procedures are in place to protect confidential information from erasure or destruction during the specified retention period of the information",
			"Attributes": [
			  {
				"ItemId": "cc_c_1_1",
				"Section": "CCC1.0 - Additional Criterial for Confidentiality",
				"Service": "aws",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "rds_instance_deletion_protection"
			]
		  },
		  {
			"Id": "cc_c_1_2",
			"Name": "C1.2 The entity disposes of confidential information to meet the entity’s objectives related to confidentiality",
			"Description": "Identifies Confidential Information for Destruction - Procedures are in place to identify confidential information requiring destruction when the end of the retention period is reached. Destroys Confidential Information - Procedures are in place to erase or otherwise destroy confidential information that has been identified for destruction.",
			"Attributes": [
			  {
				"ItemId": "cc_c_1_2",
				"Section": "CCC1.0 - Additional Criterial for Confidentiality",
				"Service": "s3",
				"Type": "automated"
			  }
			],
			"Checks": [
			  "s3_bucket_object_versioning"
			]
		  },
		  {
			"Id": "p_1_1",
			"Name": "P1.1 The entity provides notice to data subjects about its privacy practices to meet the entity’s objectives related to privacy",
			"Description": "The entity provides notice to data subjects about its privacy practices to meet the entity’s objectives related to privacy. The notice is updated and communicated to data subjects in a timely manner for changes to the entity’s privacy practices, including changes in the use of personal information, to meet the entity’s objectives related to privacy. Communicates to Data Subjects - Notice is provided to data subjects regarding the following: Purpose for collecting personal informationChoice and consentTypes of personal information collectedMethods of collection (for example, use of cookies or other tracking techniques)Use, retention, and disposalAccessDisclosure to third partiesSecurity for privacyQuality, including data subjects’ responsibilities for qualityMonitoring and enforcementIf personal information is collected from sources other than the individual, such sources are described in the privacy notice. Provides Notice to Data Subjects - Notice is provided to data subjects (1) at or before the time personal information is collected or as soon as practical thereafter, (2) at or before the entity changes its privacy notice or as soon as practical thereafter, or (3) before personal information is used for new purposes not previously identified. Covers Entities and Activities in Notice - An objective description of the entities and activities covered is included in the entity’s privacy notice. Uses Clear and Conspicuous Language - The entity’s privacy notice is conspicuous and uses clear language.",
			"Attributes": [
			  {
				"ItemId": "p_1_1",
				"Section": "P1.0 - Privacy Criteria Related to Notice and Communication of Objectives Related to Privacy",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_2_1",
			"Name": "P2.1 The entity communicates choices available regarding the collection, use, retention, disclosure, and disposal of personal information to the data subjects and the consequences, if any, of each choice",
			"Description": "The entity communicates choices available regarding the collection, use, retention, disclosure, and disposal of personal information to the data subjects and the consequences, if any, of each choice. Explicit consent for the collection, use, retention, disclosure, and disposal of personal information is obtained from data subjects or other authorized persons, if required. Such consent is obtained only for the intended purpose of the information to meet the entity’s objectives related to privacy. The entity’s basis for determining implicit consent for the collection, use, retention, disclosure, and disposal of personal information is documented. Communicates to Data Subjects - Data subjects are informed (a) about the choices available to them with respect to the collection, use, and disclosure of personal information and (b) that implicit or explicit consent is required to collect, use, and disclose personal information, unless a law or regulation specifically requires or allows otherwise. Communicates Consequences of Denying or Withdrawing Consent - When personal information is collected, data subjects are informed of the consequences of refusing to provide personal information or denying or withdrawing consent to use personal information for purposes identified in the notice. Obtains Implicit or Explicit Consent - Implicit or explicit consent is obtained from data subjects at or before the time personal information is collected or soon thereafter. The individual’s preferences expressed in his or her consent are confirmed and implemented. Documents and Obtains Consent for New Purposes and Uses - If information that was previously collected is to be used for purposes not previously identified in the privacy notice, the new purpose is documented, the data subject is notified, and implicit or explicit consent is obtained prior to such new use or purpose. Obtains Explicit Consent for Sensitive Information - Explicit consent is obtained directly from the data subject when sensitive personal information is collected, used, or disclosed, unless a law or regulation specifically requires otherwise.",
			"Attributes": [
			  {
				"ItemId": "p_2_1",
				"Section": "P2.0 - Privacy Criteria Related to Choice and Consent",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_3_1",
			"Name": "P3.1 Personal information is collected consistent with the entity’s objectives related to privacy",
			"Description": "Limits the Collection of Personal Information - The collection of personal information is limited to that necessary to meet the entity’s objectives. Collects Information by Fair and Lawful Means - Methods of collecting personal information are reviewed by management before they are implemented to confirm that personal information is obtained (a) fairly, without intimidation or deception, and (b) lawfully, adhering to all relevant rules of law, whether derived from statute or common law, relating to the collection of personal information. Collects Information From Reliable Sources - Management confirms that third parties from whom personal information is collected (that is, sources other than the individual) are reliable sources that collect information fairly and lawfully. Informs Data Subjects When Additional Information Is Acquired - Data subjects are informed if the entity develops or acquires additional information about them for its use.",
			"Attributes": [
			  {
				"ItemId": "p_3_1",
				"Section": "P3.0 - Privacy Criteria Related to Collection",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_3_2",
			"Name": "P3.2 For information requiring explicit consent, the entity communicates the need for such consent, as well as the consequences of a failure to provide consent for the request for personal information, and obtains the consent prior to the collection of the information to meet the entity’s objectives related to privacy",
			"Description": "Obtains Explicit Consent for Sensitive Information - Explicit consent is obtained directly from the data subject when sensitive personal information is collected, used, or disclosed, unless a law or regulation specifically requires otherwise. Documents Explicit Consent to Retain Information - Documentation of explicit consent for the collection, use, or disclosure of sensitive personal information is retained in accordance with objectives related to privacy.",
			"Attributes": [
			  {
				"ItemId": "p_3_2",
				"Section": "P3.0 - Privacy Criteria Related to Collection",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_4_1",
			"Name": "P4.1 The entity limits the use of personal information to the purposes identified in the entity’s objectives related to privacy",
			"Description": "Uses Personal Information for Intended Purposes - Personal information is used only for the intended purposes for which it was collected and only when implicit or explicit consent has been obtained unless a law or regulation specifically requires otherwise.",
			"Attributes": [
			  {
				"ItemId": "p_4_1",
				"Section": "P4.0 - Privacy Criteria Related to Use, Retention, and Disposal",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_4_2",
			"Name": "P4.2 The entity retains personal information consistent with the entity’s objectives related to privacy",
			"Description": "Retains Personal Information - Personal information is retained for no longer than necessary to fulfill the stated purposes, unless a law or regulation specifically requires otherwise. Protects Personal Information - Policies and procedures have been implemented to protect personal information from erasure or destruction during the specified retention period of the information.",
			"Attributes": [
			  {
				"ItemId": "p_4_2",
				"Section": "P4.0 - Privacy Criteria Related to Use, Retention, and Disposal",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_4_3",
			"Name": "P4.3 The entity securely disposes of personal information to meet the entity’s objectives related to privacy",
			"Description": "Captures, Identifies, and Flags Requests for Deletion - Requests for deletion of personal information are captured, and information related to the requests is identified and flagged for destruction to meet the entity’s objectives related to privacy. Disposes of, Destroys, and Redacts Personal Information - Personal information no longer retained is anonymized, disposed of, or destroyed in a manner that prevents loss, theft, misuse, or unauthorized access. Destroys Personal Information - Policies and procedures are implemented to erase or otherwise destroy personal information that has been identified for destruction.",
			"Attributes": [
			  {
				"ItemId": "p_4_3",
				"Section": "P4.0 - Privacy Criteria Related to Use, Retention, and Disposal",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_5_1",
			"Name": "P5.1 The entity grants identified and authenticated data subjects the ability to access their stored personal information for review and, upon request, provides physical or electronic copies of that information to data subjects to meet the entity’s objectives related to privacy",
			"Description": "The entity grants identified and authenticated data subjects the ability to access their stored personal information for review and, upon request, provides physical or electronic copies of that information to data subjects to meet the entity’s objectives related to privacy. If access is denied, data subjects are informed of the denial and reason for such denial, as required, to meet the entity’s objectives related to privacy. Authenticates Data Subjects’ Identity - The identity of data subjects who request access to their personal information is authenticated before they are given access to that information. Permits Data Subjects Access to Their Personal Information - Data subjects are able to determine whether the entity maintains personal information about them and, upon request, may obtain access to their personal information. Provides Understandable Personal Information Within Reasonable Time - Personal information is provided to data subjects in an understandable form, in a reasonable time frame, and at a reasonable cost, if any. Informs Data Subjects If Access Is Denied - When data subjects are denied access to their personal information, the entity informs them of the denial and the reason for the denial in a timely manner, unless prohibited by law or regulation.",
			"Attributes": [
			  {
				"ItemId": "p_5_1",
				"Section": "P5.0 - Privacy Criteria Related to Access",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_5_2",
			"Name": "P5.2 The entity corrects, amends, or appends personal information based on information provided by data subjects and communicates such information to third parties, as committed or required, to meet the entity’s objectives related to privacy",
			"Description": "The entity corrects, amends, or appends personal information based on information provided by data subjects and communicates such information to third parties, as committed or required, to meet the entity’s objectives related to privacy. If a request for correction is denied, data subjects are informed of the denial and reason for such denial to meet the entity’s objectives related to privacy. Communicates Denial of Access Requests - Data subjects are informed, in writing, of the reason a request for access to their personal information was denied, the source of the entity’s legal right to deny such access, if applicable, and the individual’s right, if any, to challenge such denial, as specifically permitted or required by law or regulation. Permits Data Subjects to Update or Correct Personal Information - Data subjects are able to update or correct personal information held by the entity. The entity provides such updated or corrected information to third parties that were previously provided with the data subject’s personal information consistent with the entity’s objective related to privacy. Communicates Denial of Correction Requests - Data subjects are informed, in writing, about the reason a request for correction of personal information was denied and how they may appeal.",
			"Attributes": [
			  {
				"ItemId": "p_5_2",
				"Section": "P5.0 - Privacy Criteria Related to Access",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_6_1",
			"Name": "P6.1 The entity discloses personal information to third parties with the explicit consent of data subjects, and such consent is obtained prior to disclosure to meet the entity’s objectives related to privacy",
			"Description": "Communicates Privacy Policies to Third Parties - Privacy policies or other specific instructions or requirements for handling personal information are communicated to third parties to whom personal information is disclosed. Discloses Personal Information Only When Appropriate - Personal information is disclosed to third parties only for the purposes for which it was collected or created and only when implicit or explicit consent has been obtained from the data subject, unless a law or regulation specifically requires otherwise. Discloses Personal Information Only to Appropriate Third Parties - Personal information is disclosed only to third parties who have agreements with the entity to protect personal information in a manner consistent with the relevant aspects of the entity’s privacy notice or other specific instructions or requirements. The entity has procedures in place to evaluate that the third parties have effective controls to meet the terms of the agreement, instructions, or requirements.",
			"Attributes": [
			  {
				"ItemId": "p_6_1",
				"Section": "P6.0 - Privacy Criteria Related to Disclosure and Notification",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_6_2",
			"Name": "P6.2 The entity creates and retains a complete, accurate, and timely record of authorized disclosures of personal information to meet the entity’s objectives related to privacy",
			"Description": "Creates and Retains Record of Authorized Disclosures - The entity creates and maintains a record of authorized disclosures of personal information that is complete, accurate, and timely.",
			"Attributes": [
			  {
				"ItemId": "p_6_2",
				"Section": "P6.0 - Privacy Criteria Related to Disclosure and Notification",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_6_3",
			"Name": "P6.3 The entity creates and retains a complete, accurate, and timely record of detected or reported unauthorized disclosures (including breaches) of personal information to meet the entity’s objectives related to privacy",
			"Description": "Creates and Retains Record of Detected or Reported Unauthorized Disclosures - The entity creates and maintains a record of detected or reported unauthorized disclosures of personal information that is complete, accurate, and timely.",
			"Attributes": [
			  {
				"ItemId": "p_6_3",
				"Section": "P6.0 - Privacy Criteria Related to Disclosure and Notification",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_6_4",
			"Name": "P6.4 The entity obtains privacy commitments from vendors and other third parties who have access to personal information to meet the entity’s objectives related to privacy",
			"Description": "The entity obtains privacy commitments from vendors and other third parties who have access to personal information to meet the entity’s objectives related to privacy. The entity assesses those parties’ compliance on a periodic and as-needed basis and takes corrective action, if necessary. Discloses Personal Information Only to Appropriate Third Parties - Personal information is disclosed only to third parties who have agreements with the entity to protect personal information in a manner consistent with the relevant aspects of the entity’s privacy notice or other specific instructions or requirements. The entity has procedures in place to evaluate that the third parties have effective controls to meet the terms of the agreement, instructions, or requirements. Remediates Misuse of Personal Information by a Third Party - The entity takes remedial action in response to misuse of personal information by a third party to whom the entity has transferred such information.",
			"Attributes": [
			  {
				"ItemId": "p_6_4",
				"Section": "P6.0 - Privacy Criteria Related to Disclosure and Notification",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_6_5",
			"Name": "P6.5 The entity obtains commitments from vendors and other third parties with access to personal information to notify the entity in the event of actual or suspected unauthorized disclosures of personal information",
			"Description": "The entity obtains commitments from vendors and other third parties with access to personal information to notify the entity in the event of actual or suspected unauthorized disclosures of personal information. Such notifications are reported to appropriate personnel and acted on in accordance with established incident response procedures to meet the entity’s objectives related to privacy. Remediates Misuse of Personal Information by a Third Party - The entity takes remedial action in response to misuse of personal information by a third party to whom the entity has transferred such information. Reports Actual or Suspected Unauthorized Disclosures - A process exists for obtaining commitments from vendors and other third parties to report to the entity actual or suspected unauthorized disclosures of personal information.",
			"Attributes": [
			  {
				"ItemId": "p_6_5",
				"Section": "P6.0 - Privacy Criteria Related to Disclosure and Notification",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_6_6",
			"Name": "P6.6 The entity provides notification of breaches and incidents to affected data subjects, regulators, and others to meet the entity’s objectives related to privacy",
			"Description": "Remediates Misuse of Personal Information by a Third Party - The entity takes remedial action in response to misuse of personal information by a third party to whom the entity has transferred such information. Reports Actual or Suspected Unauthorized Disclosures - A process exists for obtaining commitments from vendors and other third parties to report to the entity actual or suspected unauthorized disclosures of personal information.",
			"Attributes": [
			  {
				"ItemId": "p_6_6",
				"Section": "P6.0 - Privacy Criteria Related to Disclosure and Notification",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_6_7",
			"Name": "P6.7 The entity provides data subjects with an accounting of the personal information held and disclosure of the data subjects’ personal information, upon the data subjects’ request, to meet the entity’s objectives related to privacy",
			"Description": "Identifies Types of Personal Information and Handling Process - The types of personal information and sensitive personal information and the related processes, systems, and third parties involved in the handling of such information are identified. Captures, Identifies, and Communicates Requests for Information - Requests for an accounting of personal information held and disclosures of the data subjects’ personal information are captured, and information related to the requests is identified and communicated to data subjects to meet the entity’s objectives related to privacy.",
			"Attributes": [
			  {
				"ItemId": "p_6_7",
				"Section": "P6.0 - Privacy Criteria Related to Disclosure and Notification",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_7_1",
			"Name": "P7.1 The entity collects and maintains accurate, up-to-date, complete, and relevant personal information to meet the entity’s objectives related to privacy",
			"Description": "Ensures Accuracy and Completeness of Personal Information - Personal information is accurate and complete for the purposes for which it is to be used. Ensures Relevance of Personal Information - Personal information is relevant to the purposes for which it is to be used.",
			"Attributes": [
			  {
				"ItemId": "p_7_1",
				"Section": "P7.0 - Privacy Criteria Related to Quality",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  },
		  {
			"Id": "p_8_1",
			"Name": "P8.1 The entity implements a process for receiving, addressing, resolving, and communicating the resolution of inquiries, complaints, and disputes from data subjects and others and periodically monitors compliance to meet the entity’s objectives related to privacy",
			"Description": "The entity implements a process for receiving, addressing, resolving, and communicating the resolution of inquiries, complaints, and disputes from data subjects and others and periodically monitors compliance to meet the entity’s objectives related to privacy. Corrections and other necessary actions related to identified deficiencies are made or taken in a timely manner. Communicates to Data Subjects—Data subjects are informed about how to contact the entity with inquiries, complaints, and disputes. Addresses Inquiries, Complaints, and Disputes - A process is in place to address inquiries, complaints, and disputes. Documents and Communicates Dispute Resolution and Recourse - Each complaint is addressed, and the resolution is documented and communicated to the individual. Documents and Reports Compliance Review Results - Compliance with objectives related to privacy are reviewed and documented, and the results of such reviews are reported to management. If problems are identified, remediation plans are developed and implemented. Documents and Reports Instances of Noncompliance - Instances of noncompliance with objectives related to privacy are documented and reported and, if needed, corrective and disciplinary measures are taken on a timely basis. Performs Ongoing Monitoring - Ongoing procedures are performed for monitoring the effectiveness of controls over personal information and for taking timely corrective actions when necessary.",
			"Attributes": [
			  {
				"ItemId": "p_8_1",
				"Section": "P8.0 - Privacy Criteria Related to Monitoring and Enforcement",
				"Service": "aws",
				"Type": "manual"
			  }
			],
			"Checks": []
		  }
		]
	  }
	  `
	var comp CFramework
	err := json.Unmarshal([]byte(jsonData), &comp)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Create a new Go file and write the contents
	file, err := os.Create("requirements.go")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	// Write package declaration
	file.WriteString("package main\n\n")

	// Write struct definitions
	file.WriteString("type NistComp struct {\n")
	file.WriteString("\tProvider string\n")
	file.WriteString("\tFramework string\n")
	file.WriteString("\tFrameworkdesc string\n")
	file.WriteString("\tId string\n")
	file.WriteString("\tName string\n")
	file.WriteString("\tDescription string\n")
	file.WriteString("\tItemId string\n")
	file.WriteString("\tSection string\n")
	file.WriteString("\tSubSection string\n")
	file.WriteString("\tService string\n")
	file.WriteString("\tType string\n")
	file.WriteString("\tChecks []string\n")
	file.WriteString("}\n\n")

	// Write requirements list
	// file.WriteString("var Requirements = []Requirement{\n")
	var provider = "AWS"
	var framework = "SOC2"
	var Frameworkdesc = "System and Organization Controls (SOC), defined by the American Institute of Certified Public Accountants (AICPA), is the name of a set of reports that's produced during an audit. It's intended for use by service organizations (organizations that provide information systems as a service to other organizations) to issue validated reports of internal controls over those information systems to the users of those services. The reports focus on controls grouped into five categories known as Trust Service Principles."
	var i int64
	for _, req := range comp.Requirements {
		i++
		file.WriteString(fmt.Sprintf("\tvar soc2_%s = &NistComp{\n", req.Id))
		file.WriteString(fmt.Sprintf("\t\tFramework: \"%s\",\n", framework))
		file.WriteString(fmt.Sprintf("\t\tProvider: \"%s\",\n", provider))
		file.WriteString(fmt.Sprintf("\t\tFrameworkdesc: \"%s\",\n", Frameworkdesc))
		file.WriteString(fmt.Sprintf("\t\tId: \"%s\",\n", req.Id))
		file.WriteString(fmt.Sprintf("\t\tName: \"%s\",\n", req.Name))
		file.WriteString(fmt.Sprintf("\t\tDescription: \"%s\",\n", req.Description))
		// file.WriteString(fmt.Sprintf("\t\tAttributes: []struct {\n"))
		for _, attr := range req.Attributes {
			if attr.ItemId != "" {
				file.WriteString(fmt.Sprintf("\t\tItemId: \"%s\",\n", attr.ItemId))
			}
			if attr.Section != "" {
				file.WriteString(fmt.Sprintf("\t\tSection: \"%s\",\n", attr.Section))
			}
			if attr.SubSection != "" {
				file.WriteString(fmt.Sprintf("\t\tSubSection: \"%s\",\n", attr.SubSection))
			}
			if attr.Service != "" {
				file.WriteString(fmt.Sprintf("\t\tService: \"%s\",\n", attr.Service))
			}

			if attr.Service != "" {
				file.WriteString(fmt.Sprintf("\t\tType: \"%s\",\n", attr.Type))
			}
		}
		// file.WriteString(fmt.Sprintf("\t\t},\n"))
		file.WriteString(fmt.Sprintf("\t\tChecks: %#v,\n", req.Checks))
		file.WriteString(fmt.Sprintf("\t}\n"))

	}
	fmt.Println(i)

}