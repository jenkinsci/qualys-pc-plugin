# Qualys PC(Policy Compliance) Scanning Connector for Jenkins

## About

The Qualys Policy Compliance Scanning Connector empowers the DevOps to automate the PC scanning of host or cloud instance from Jenkins. By integrating scans in this manner, Host or cloud instance security testing is accomplished to discover and eliminate policy compliance related flaws.

## How to use this plugin

### Prerequisites

* A valid Qualys subscription with access to PC(Policy Compliance) module and Qualys APIs.
* Create custom Option Profiles in Qualys account meant for Jenkins usecase. These Option profiles must be created with title starting with 'Jenkins_' and required policies added to it. 

### Where to use this plugin step

This plugin step can be configured during "Post-build" phase of your job, right after you build your host/cloud instance. 

### Configuration

If you are using pipeline, you should go to "Pipeline Syntax", and select `qualysPolicyComplianceScanner` step.
If you are using freestyle, you should add `Scan host/instances with Qualys PC` post-build step.

A form appears with several input fields. Now you are ready to configure the plugin. 

#### Qualys Credentials

1. Enter your Qualys API Server URL. 
2. Select/Add your Qualys API Credentials.
3. If you need proxy to communicate to the Internet, set correct proxy settings. 
4. To confirm that Jenkins can communicate to Qualys Cloud Platform and APIs, use `Test Connection` button.

#### Configure Scan Options

1. In the "Scan Title" field, provide scan title for the PC Scan. By default, the scan title will be: [job_name]_jenkins_build_[build_number] + timestamp. You can edit the scan title, but a timestamp will automatically be appended regardless.
2. You can choose the "Target" as either Host IP or Cloud Instance (AWS EC2).
3. For Host IP, enter the IP to scan.
4. For Cloud Instance: 
	- Provide ID of Amazon EC2 Instance on which you want to launch the PC scan. 
	- Select the connector name for the instance.
	- When you select the "Run selected EC2 connector" check box, we run the connector to get the updated information about the instance and then launch the scan if the instance status is not known. If we have the instance status information, we do not run the connector and directly launch the scan. By default, this check box is not selected.
5. Next, create a Windows or Unix authentication record that we will use to authenticate to your Unix or Windows host for PC scan.
   To create an authentication record, select the platform (Windows/Unix) and credentials of your host. This step is optional if you have an authentication record created for the host in your account. 
   plugin follow this naming convention when saving the authentication record: 
   - For Windows: Jenkins_windows_[Job Name]
   - For Unix: Jenkins_unix_[Job Name]
6. Next, configure scan parameters:
	- Scanner Name: Select the scanner appliance name from the drop-down that PC will use to scan your host assets on your network or on an EC2 instance to check the compliance of your systems against your policies. Default value is External scanner if you do not select a scanner from the Scanner drop-down. 
	- Option Profile: The option profile contains the settings used for a compliance scan such as controls and ports selections for scan, settings for automatic authentication record creation by system and so on. Select the option profile and the policies that you want the plugin to scan.
		Option profiles must fulfill these conditions for plugin to use them during policy scan:
		> The option profiles that you want to use for PC scan must have names starting with Jenkins_. For example: Jenkins_myoption_profile. We will show only those option profiles from your account in the Option Profile drop-down that have names starting with "Jenkins_".
		> The option profiles must be associated with one or more policies that you want to scan.
		
#### Configure Scan Pass/Fail Criteria

1. Fail by State AND Criticality: This criteria lets you choose the states and the corresponding criticality to fail a build. The build will fail if both the state and criticality condition is fulfilled. 
   The build can be failed for all or any of these states for the controls you are evaluating: Fail, Error and Exceptions and any or all of these criticalities: Serious, Urgent, Critical, Medium and Minimal. 
2. Fail by Authentication Failure: This criteria if selected will fail the build if the plugin fails to authenticate to the host IP or EC2 Instance using the authentication record. If this option is not selected and yet the authenticaton fails, we will pass the build but no reports will be generated.
3. Exclude Condition: You can use the Exclude Conditions option to ignore specified CIDs or Control IDs while evaluating the policy for failure conditions. For example, we will not fail a build if an excluded CID is detected for a policy in the scan even if that CID meets the specified failure condition. We evaluate the Exclude conditions first and remove the CIDs that matches the exclude conditions before evaluating the Failure Conditions.

#### Timeout Settings

In the Timeout settings, specify the polling frequency in minutes for collecting the PC scan status data and the timeout duration for getting the scan result.

### Generate Pipeline Script *(for pipeline project only)*

If you are configuring pipeline project, click the `Generate Pipeline Script` button/link. It will give you a command which you can copy and paste in your project's pipeline script. 

## How this plugin works

When the plugin step runs, 
1. Plugin first adds input host IP Address into Qualys user Account. In case of EC2 instance plugin will first fetch private IP address of instance and then add it into user account.
2. If 'Create Authentication Record' checkbox is checked, plugin will create/update authentication record with provided credentials and platform for the input host ip.
3. Create/Update Asset group with provided IP.
4. Update all selected policies with newly created/updated asset group.
5. Launch a scan on the configured Host or cloud instance with the configured scan options.
6. If you have configured any pass/fail criteria, the plugin evaluates the response against that. If any of the build failure criteria matches, it will fail the build. Otherwise, your build job proceeds to next step (if any).

### Known Issues
* In v1.0.6, Policy Selection box may not populate policies on Pipeline Snippet generator (PFB), however, when clicked on 'Generate Pipeline Script', script is generated with all the policies under selected Option Profile correctly.
* Hotfix for this issue will be released in v1.0.7 in January 2024.
<img width="665" alt="option profile" src="https://github.com/jenkinsci/qualys-pc-plugin/assets/143092348/2a154777-1b0a-41b1-9ce2-7ee15652b171">


