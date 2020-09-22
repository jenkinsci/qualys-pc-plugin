/* This file is responsible for the execution of the Job Steps*/
package com.qualys.plugins.pc;

import java.io.IOException;
import java.io.PrintStream;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import com.google.gson.JsonObject;
import com.qualys.plugins.pc.auth.QualysAuth;
import com.qualys.plugins.pc.client.QualysPCClient;
import com.qualys.plugins.pc.client.QualysPCResponse;
import com.qualys.plugins.pc.report.ReportAction;
import com.qualys.plugins.pc.util.BuildFailedException;
import com.qualys.plugins.pc.util.Helper;
import com.qualys.plugins.pc.util.ScanErrorException;
import com.qualys.plugins.pc.util.TimeOutException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.model.Run;
import hudson.model.TaskListener;

public class PCScanLauncher {
	private Run<?, ?> run;
	private TaskListener listener;
	private PrintStream buildLogger;
	private String hostIp;
	private String ec2Id;
	private String ec2ConnName;
	private String ec2Endpoint;
	private String scannerName;
	private String scanName;
	private String scanNameResolved;
	private String optionProfile;
	private JSONObject selectedPoliciesJson;
	private int pollingIntervalForVulns;
	private int vulnsTimeout;
	private String scanStatus = null;
	private String subScanStatus = "";
	private boolean useHost;
	private boolean useEc2;

	private QualysAuth auth;
	String ipAddress;

	private QualysPCClient apiClient;
	private String excludedCids;
	private boolean failByAuth;
	private boolean criticalityMinimal;
	private boolean criticalityMedium;
	private boolean criticalityCritical;
	private boolean criticalityUrgent;
	private boolean criticalitySerious;
	private boolean stateExceptions;
	private boolean stateError;
	private boolean stateFail;
	String ec2PrivateIpAddress;
	private String unixAndWindowsCredentialsId;
	private String unixAndWindowsCredentials;
	private String job_name;
	private String scanId;
	private String scanRef;
	private String scanDuration;
	private String scanLaunchDate;
	private String authRecord;
	private String assetGroupId;
	private boolean failByStateAndCriticality;
	private boolean excludedCriteria;

	private final static Logger logger = Helper.getLogger(PCScanLauncher.class.getName());
	private final static int DEFAULT_POLLING_INTERVAL_FOR_VULNS = 2; // 2 minutes
	private final static int DEFAULT_TIMEOUT_FOR_VULNS = 60; // 1Hrs

	public PCScanLauncher(Run<?, ?> run, TaskListener listener, String hostIp, String ec2Id, String ec2ConnName,
			String ec2Endpoint, String ec2PrivateIpAddress, String scannerName, String scanName, String optionProfile,
			String pollingIntervalStr, String vulnsTimeoutStr, boolean useHost, boolean useEc2, QualysAuth auth,
			JSONObject selectedPoliciesJson, boolean stateFail, boolean stateError, boolean stateExceptions,
			boolean criticalitySerious, boolean criticalityUrgent, boolean criticalityCritical,
			boolean criticalityMedium, boolean criticalityMinimal, boolean failByAuth, String excludedCids,
			String unixAndWindowsCredentialsId, String unixAndWindowsCredentials, boolean failByStateAndCriticality,
			boolean excludedCriteria) throws IOException, InterruptedException {

		this.run = run;
		this.listener = listener;
		this.buildLogger = listener.getLogger();
		this.useHost = useHost;
		this.hostIp = hostIp;
		this.scanName = scanName.trim();
		this.scannerName = scannerName;
		this.useEc2 = useEc2;
		this.ec2Id = ec2Id;
		this.ec2ConnName = ec2ConnName;
		this.ec2Endpoint = ec2Endpoint;
		this.ec2PrivateIpAddress = ec2PrivateIpAddress;
		this.optionProfile = optionProfile;
		this.auth = auth;
		this.selectedPoliciesJson = selectedPoliciesJson;
		this.unixAndWindowsCredentialsId = unixAndWindowsCredentialsId;
		this.unixAndWindowsCredentials = unixAndWindowsCredentials;
		this.failByStateAndCriticality = failByStateAndCriticality;

		this.stateFail = stateFail;
		this.stateError = stateError;
		this.stateExceptions = stateExceptions;

		this.criticalitySerious = criticalitySerious;
		this.criticalityUrgent = criticalityUrgent;
		this.criticalityCritical = criticalityCritical;
		this.criticalityMedium = criticalityMedium;
		this.criticalityMinimal = criticalityMinimal;

		this.failByAuth = failByAuth;
		this.excludedCids = excludedCids;
		this.excludedCriteria = excludedCriteria;

		if (this.scanName != null && !this.scanName.isEmpty()) {
			this.scanName += "_[timestamp]";
		}

		this.pollingIntervalForVulns = setTimeoutInMinutes("pollingInterval", DEFAULT_POLLING_INTERVAL_FOR_VULNS,
				pollingIntervalStr, listener);
		this.vulnsTimeout = setTimeoutInMinutes("vulnsTimeout", DEFAULT_TIMEOUT_FOR_VULNS, vulnsTimeoutStr, listener);
		this.apiClient = new QualysPCClient(this.auth, System.out, this.pollingIntervalForVulns, this.vulnsTimeout,
				listener);

		EnvVars env = run.getEnvironment(listener);
		this.job_name = env.get("JOB_NAME").replace(",", "_");

	} // end of Xtor

	private int setTimeoutInMinutes(String timeoutType, int defaultTimeoutInMins, String timeout,
			TaskListener listener) {
		if (!(timeout == null || timeout.isEmpty())) {
			try {
				// calculate the timeout in seconds
				String[] numbers = timeout.split("\\*");
				int timeoutInMins = 1;
				for (int i = 0; i < numbers.length; ++i) {
					timeoutInMins *= Long.parseLong(numbers[i]);
				}
				return timeoutInMins;
			} catch (Exception e) {
				String error = " Invalid " + timeoutType + " time value. Cannot parse -" + e.getMessage() + "\n";
				error = error + " Using default period of "
						+ (timeoutType.equals("vulnsTimeout") ? "60" : defaultTimeoutInMins) + " minutes for "
						+ timeoutType + ".";
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
				logger.info(error);
			}
		}
		return defaultTimeoutInMins;
	}

	private String getFailureConditionMsg() {
		String msg = "";
		List<String> state = new ArrayList<String>();
		List<String> criticality = new ArrayList<String>();

		if (failByStateAndCriticality) {
			if (this.stateFail) {
				state.add("Fail");
			}
			if (this.stateError) {
				state.add("Error");
			}
			if (this.stateExceptions) {
				state.add("Exceptions");
			}
			if (this.criticalitySerious) {
				criticality.add("Serious");
			}
			if (this.criticalityUrgent) {
				criticality.add("Urgent");
			}
			if (this.criticalityCritical) {
				criticality.add("Critical");
			}
			if (this.criticalityMedium) {
				criticality.add("Medium");
			}
			if (this.criticalityMinimal) {
				criticality.add("Minimal");
			}
			for (int i = 0; i < state.size(); i++) {
				msg = msg + state.get(i);
				if (i != state.size() - 1) {
					msg = msg + " OR ";
				}
			}
			msg = "(" + msg + ") State AND (";
			for (int i = 0; i < criticality.size(); i++) {
				msg = msg + criticality.get(i);
				if (i != criticality.size() - 1) {
					msg = msg + " OR ";
				}
			}
			msg = msg + ") Criticality.";
		} else {
			msg = "Fail by State And Criticality conditions are not configured.";
		}
		return msg;
	}

	private String getFailCriteria() {
		String strFailCriteria = "";
		List<String> state = new ArrayList<String>();
		List<String> criticality = new ArrayList<String>();

		if (failByStateAndCriticality) {
			if (this.stateFail) {
				state.add("Failed");
			}
			if (this.stateError) {
				state.add("Error");
			}
			if (this.stateExceptions) {
				state.add("Exceptions");
			}
			if (this.criticalitySerious) {
				criticality.add("SERIOUS");
			}
			if (this.criticalityUrgent) {
				criticality.add("URGENT");
			}
			if (this.criticalityCritical) {
				criticality.add("CRITICAL");
			}
			if (this.criticalityMedium) {
				criticality.add("MEDIUM");
			}
			if (this.criticalityMinimal) {
				criticality.add("MINIMAL");
			}
			for (int i = 0; i < state.size(); i++) {
				strFailCriteria = strFailCriteria + state.get(i);
				if (i != state.size() - 1) {
					strFailCriteria = strFailCriteria + "|";
				}
			}
			strFailCriteria = strFailCriteria + ",";
			for (int i = 0; i < criticality.size(); i++) {
				strFailCriteria = strFailCriteria + criticality.get(i);
				if (i != criticality.size() - 1) {
					strFailCriteria = strFailCriteria + "|";
				}
			}
		}
		return strFailCriteria;

	}

	public void getAndProcessLaunchReport() throws Exception {
		boolean failBuild = false;
		List<PCReportLauncher> thread = new ArrayList<PCReportLauncher>();
		List<String> policyIds = new ArrayList<String>();
		List<String> policyNames = new ArrayList<String>();
		int totalControlFailCount = 0;

		for (int i = 0; i < selectedPoliciesJson.length(); i++) {

			String policyId = selectedPoliciesJson.names().getString(i);
			String policyName = (String) selectedPoliciesJson.get(selectedPoliciesJson.names().getString(i));

			policyIds.add(policyId);

			policyNames.add(policyName);

			PCReportLauncher pcReport = new PCReportLauncher(run, listener, ec2Id, ec2ConnName, scannerName, useHost,
					useEc2, auth, policyId, policyName, pollingIntervalForVulns, apiClient, this.ipAddress,
					this.stateFail, this.stateError, this.stateExceptions, this.criticalitySerious,
					this.criticalityUrgent, this.criticalityCritical, this.criticalityMedium, this.criticalityMinimal,
					this.failByAuth, this.excludedCids, this.assetGroupId, this.failByStateAndCriticality,
					this.excludedCriteria);
			thread.add(pcReport);
			pcReport.start();
		}
		for (PCReportLauncher t : thread) {
			t.join();
		}

		String policyDataNotFound = "";
		for (PCReportLauncher t : thread) {
			if (t.getControlFail()) {
				failBuild = true;
			}
			if (t.getFailControlCount() != -1) {
				totalControlFailCount += t.getFailControlCount();
				if (this.failByStateAndCriticality) {
					String msg = " Found " + t.getFailControlCount() + " controls failing by criteria for policy "
							+ t.policyName + ".";
					logger.info(msg);
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + msg);
				}
			} else {
				policyDataNotFound += "\"" + t.policyName + "\",";
			}

		}

		ReportAction action = new ReportAction(run, this.scanId, scanNameResolved, this.scanRef, this.scanDuration,
				this.scanLaunchDate, this.authRecord, this.ipAddress, this.auth.getServer(),
				this.auth.getServerPlatformUrl(), this.auth.getUsername(), this.auth.getPassword(),
				this.auth.getUseProxy(), this.auth.getProxyServer(), this.auth.getProxyPort(),
				this.auth.getProxyUsername(), this.auth.getProxyPassword(), failBuild & this.failByStateAndCriticality,
				policyIds, policyNames, this.excludedCids, this.excludedCriteria, getFailCriteria());

		run.addAction(action);

		if (failBuild) {
			String error = "";
			if (totalControlFailCount > 0) {
				error = " Qualys PC Connector has found total " + totalControlFailCount
						+ " controls (including all policies) falling under configured Build failure condition - "
						+ this.getFailureConditionMsg() + " ";
			}
			if (policyDataNotFound.length() > 0) {
				policyDataNotFound = "Data not found for policies: " + policyDataNotFound;
				policyDataNotFound = policyDataNotFound.substring(0, policyDataNotFound.length() - 1);
				policyDataNotFound = policyDataNotFound + ".";

				error += policyDataNotFound;
			}
			logger.info(error);
			// buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
			if (this.failByStateAndCriticality) {
				throw new BuildFailedException(error);
			}
		}

	}// End of getAndProcessLaunchReport method

	public boolean checkScanResult(String scanRef) throws Exception {
		boolean scanAuthFail = false;
		String authFailIP = "";

		QualysPCResponse statusResponse = apiClient.getPCScanResult(scanRef);
		Document result = null;
		result = statusResponse.getResponseXml();

		try {
			NodeList reportResults = result.getElementsByTagName("AUTHENTICATION");
			if (result.getElementsByTagName("AUTHENTICATION").getLength() > 0) {
				Node reportResult = reportResults.item(0);
				Element eElement = (Element) reportResult;

				try {
					// Checking Host IP in FAILED Tag
					authFailIP = eElement.getElementsByTagName("FAILED").item(0).getTextContent().trim();
				} catch (Exception e) {
					logger.info("Cheking Authentication Failure. Provided host not found in AUTHENTICATION FAILED Tag");
				}
				try {
					// Checking Host IP in INSUFFICIENT Tag
					authFailIP = eElement.getElementsByTagName("INSUFFICIENT").item(0).getTextContent().trim();
				} catch (Exception e) {
					logger.info(
							"Cheking Authentication Failure. Provided host not found in AUTHENTICATION INSUFFICIENT Tag");
				}
			}

		} catch (Exception e) {
			String error = " FAILED key not found in AUTHENTICATION section. ";
			logger.info(error);
		}
		if (authFailIP.matches(this.ipAddress)) {
			if (this.failByAuth) {
				String error = "Authentication failed for Host IP : " + this.ipAddress
						+ " And Fail by Authentication Failure is True";
				logger.info(error);
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
				throw new BuildFailedException("Authentication failed for Host IP : " + this.ipAddress
						+ " And Fail by Authentication Failure is True");
			} else {
				scanAuthFail = true;
				String error = "Authentication failed for Host IP : " + this.ipAddress;
				logger.info(error);
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
			}
		}
		return scanAuthFail;
	}// end of checkScanResult

	/*
	 * This method is called in the launchHostScan method under PCScanNotifiers
	 * class
	 */
	public boolean getLaunchScanResult() throws Exception {
		try {
			Map<String, String> scanMap = launchScan();
			this.scanRef = scanMap.get("scanRef");
			this.scanId = scanMap.get("scanId");

			if (scanRef != null && !scanRef.equals("") && scanId != null && !scanId.equals("")) {
				buildLogger.println(new Timestamp(System.currentTimeMillis())
						+ " New Scan launched successfully. Scan ID: " + scanId + " & Scan Reference: " + scanRef);
			} else {
				String errorCode = scanMap.get("errorCode");
				String errorText = scanMap.get("errorText");
				if (useHost)
					throw new BuildFailedException("API Error. Could not launch new scan."
							+ "\nReason:\n\tAPI Error Code: " + errorCode + "\n\tAPI Error Message: " + errorText);
				if (useEc2)
					throw new BuildFailedException("API Error. Could not launch new scan."
							+ "\nReason:Could not find the provided instance ID with a given EC2 configuration. "
							+ "The user might have provided the wrong instance/connector/scanner details. "
							+ "Re-check EC2 details provided for the scan." + "\n\tAPI Error Code: " + errorCode
							+ "\n\tAPI Error Message: " + errorText);
			}

			String ref = waitForScanComplete(scanRef);

			// Check authentication fails.
			boolean scanAuthFail = checkScanResult(ref);
			if (this.subScanStatus == "Scan Successful" && scanAuthFail == false) {
				return true;
			} else {
				if (this.failByStateAndCriticality) {
					String error = "Launched Scan Fail. Scan Status: " + scanStatus + " | Sub Scan Status: "
							+ this.subScanStatus;
					logger.info(error);
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
					throw new BuildFailedException(error);
				} else {
					return false;
				}
			}

		} catch (BuildFailedException e) {
			throw e;
		} catch (AbortException e) {
			String error = " AbortException while getting and processing Launch Scan Result. " + e;
			logger.info(error);
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
			throw new Exception(e.getMessage());
		} catch (Exception e) {
			String error = " Exception while getting and processing Launch Scan Result. " + e;
			logger.info(error);
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
			throw new Exception(e.getMessage());
		}
	}// End of getAndProcessLaunchScanResult method

	@SuppressWarnings("null")
	public String waitForScanComplete(String scanIdRef) throws TimeOutException, Exception {
		long startTime = System.currentTimeMillis();
		long vulnsTimeoutInMillis = TimeUnit.MINUTES.toMillis(vulnsTimeout);
		long pollingInMillis = TimeUnit.MINUTES.toMillis(pollingIntervalForVulns);

		String scanStatus = null;
		try {
			while ((scanStatus = getScanFinishedStatus(scanIdRef)) == null) {
				long endTime = System.currentTimeMillis();
				if ((endTime - startTime) > vulnsTimeoutInMillis) {
					buildLogger.println(new Timestamp(System.currentTimeMillis())
							+ " Failed to get scan result; timeout of " + vulnsTimeout + " minutes reached.");
					throw new TimeOutException("Timeout reached.");
				}
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Waiting for "
						+ pollingIntervalForVulns
						+ " minute(s) before making next attempt for scanResult of Scan Reference:" + scanIdRef);
				Thread.sleep(pollingInMillis);
			}
			if (scanStatus != null && scanStatus.equalsIgnoreCase("error")) {
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " The scan(Scan Reference: " + scanIdRef
						+ ") is not completed due to an error.");
				throw new ScanErrorException(
						"The scan(Scan Reference: " + scanIdRef + ") is not completed due to an error.");
			}
		} catch (TimeOutException e) {
			String error = " Exception: Timeout reached.";
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
			logger.info(error);
			throw e;
		} catch (ScanErrorException e) {
			String error = " Exception: The scan got into an ERROR. Please check the status of the scan on Qualys POD.";
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
			logger.info(error);
			throw e;
		} catch (Exception e) {
			if (!scanIdRef.isEmpty()) {
				Map<String, String> printMap = new HashMap<String, String>();
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " User Have Aborted!!\n"
						+ new Timestamp(System.currentTimeMillis()) + " Cancelling the scan with Scan Reference: "
						+ scanIdRef);
				try {
					QualysPCResponse response = apiClient.cancelPcScan(scanIdRef);
					Document result = response.getResponseXml();
					NodeList error = result.getElementsByTagName("RESPONSE");
					for (int temp = 0; temp < error.getLength(); temp++) {
						Node nNode = error.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eElement = (Element) nNode;
							if (eElement.getElementsByTagName("CODE").getLength() != 0) {
								printMap.put("errorCode",
										eElement.getElementsByTagName("CODE").item(0).getTextContent().trim());
							} else {
								printMap.put("errorCode", "No code returned.");
							}
							if (eElement.getElementsByTagName("TEXT").getLength() != 0) {
								printMap.put("errorText",
										eElement.getElementsByTagName("TEXT").item(0).getTextContent().trim());
							} else {
								printMap.put("errorText", "No text returned");
							}
						}
					}
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + "\tAPI Response Code: "
							+ printMap.get("errorCode").toString() + "\n\tAPI Response Message: "
							+ printMap.get("errorText").toString());
				} catch (Exception e1) {
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + "\tAPI Response Code: "
							+ printMap.get("errorCode").toString() + "\n\tAPI Response Message: "
							+ printMap.get("errorText").toString());
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Error:" + e1.getMessage());
				}
			} else {
				buildLogger.println(
						new Timestamp(System.currentTimeMillis()) + " Aborting the build, scan was not launched!");
			}
			throw e;
		}

		if (scanStatus.equalsIgnoreCase("finished")) {
			return scanIdRef;
		}
		if (scanStatus.equalsIgnoreCase("canceled") && failByStateAndCriticality) {
			throw new Exception("The scan(Scan Reference: " + scanIdRef
					+ ") has been canceled. Please check the status of the scan on Qualys POD.");
		}
		if (scanStatus.equalsIgnoreCase("error") && failByStateAndCriticality) {
			throw new Exception("The scan(Scan Reference: " + scanIdRef
					+ ") is not completed due to an error. Please check the status of the scan on Qualys POD.");
		}
		return scanIdRef;
	} // end of fetchScanResult

	public String getScanFinishedStatus(String scanIdRef) {
		Document result = null;
		try {
			QualysPCResponse response = apiClient.pCScansList(scanIdRef);
			result = response.getResponseXml();

			Integer respCodeObj = response.getResponseCode();
			if (respCodeObj == null || respCodeObj != 200) {
				String error = response.getErrorMessage().toString();
				buildLogger.println(new Timestamp(System.currentTimeMillis())
						+ " Error while fetching the scan result after scan launch. Server returned: " + error
						+ ". Please do retry after sometime.");
				logger.info("Error while fetching the scan result after scan launch. Server returned: " + error
						+ ". Please do retry after sometime.");
				throw new AbortException("Error while fetching the scan result after scan launch. Server returned: "
						+ error + ". Please do retry after sometime.");
			} else {
				NodeList scanList = result.getElementsByTagName("SCAN");
				for (int temp = 0; temp < scanList.getLength(); temp++) {
					Node nNode = scanList.item(temp);
					if (nNode.getNodeType() == Node.ELEMENT_NODE) {
						Element eElement = (Element) nNode;
						if (eElement.getElementsByTagName("DURATION") != null) {
							this.scanDuration = eElement.getElementsByTagName("DURATION").item(0).getTextContent()
									.trim();
						}
						if (eElement.getElementsByTagName("STATE") != null) {
							this.scanStatus = eElement.getElementsByTagName("STATE").item(0).getTextContent().trim();
						}
						if (eElement.getElementsByTagName("LAUNCH_DATETIME") != null) {
							this.scanLaunchDate = eElement.getElementsByTagName("LAUNCH_DATETIME").item(0)
									.getTextContent().trim();
						}
						if (eElement.getElementsByTagName("STATE").item(0).getTextContent().trim()
								.equalsIgnoreCase("Finished")) {
							if (eElement.getElementsByTagName("SUB_STATE").getLength() > 0) {
								this.subScanStatus = eElement.getElementsByTagName("SUB_STATE").item(0).getTextContent()
										.trim();
							} else {
								this.subScanStatus = "Scan Successful";
							}
						}

					} // End of if
				} // End of for

				if (scanStatus.equalsIgnoreCase("error") || scanStatus.equalsIgnoreCase("canceled")
						|| (scanStatus.equalsIgnoreCase("finished"))) {
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Scan Status: " + scanStatus
							+ " | Sub Scan Status: " + this.subScanStatus);
					logger.info("Scan Status: " + scanStatus + " | Sub Scan Status: " + this.subScanStatus);
				} else {
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Scan Status: " + scanStatus);
					logger.info("Scan Status: " + scanStatus);
				}
				return (scanStatus.equalsIgnoreCase("error") || scanStatus.equalsIgnoreCase("canceled")
						|| scanStatus.equalsIgnoreCase("finished")) ? scanStatus : null;
			}
		} catch (Exception e) {
			String error = " Exception in scanStatus. " + e.getMessage();
			logger.info(error);
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
		}
		return scanStatus;
	}// end of getScanFinishedStatus

	private String isAuthRecordPresent(String platform) throws Exception {
		QualysPCResponse response = new QualysPCResponse();

		if (platform == "UNIX") {
			response = apiClient.listUnixAuthRecord("Jenkins_Unix_" + this.job_name);
			if (response.getResponseCode() == 200) {
				Document result = response.getResponseXml();
				String recordId = null;
				NodeList authRecords = result.getElementsByTagName("AUTH_UNIX");
				for (int i = 0; i < authRecords.getLength(); i++) {
					Node record = authRecords.item(i);
					Element rElement = (Element) record;
					String title = rElement.getElementsByTagName("TITLE").item(0).getTextContent().trim();
					if (title.matches("Jenkins_Unix_" + this.job_name)) {
						recordId = rElement.getElementsByTagName("ID").item(0).getTextContent().trim();
						break;
					}
				}
				if (recordId != null) {
					buildLogger
							.println("Unix Authentication Record Jenkins_Unix_" + this.job_name + " already exists.");
					return result.getElementsByTagName("ID").item(0).getTextContent().trim();
				} else {
					buildLogger
							.println("Unix Authentication Record Jenkins_Unix_" + this.job_name + " is not present.");
					return null;
				}
			} else {
				throw new BuildFailedException(
						"Failed to list Unix Authentication Record Name: Jenkins_Unix_" + this.job_name);
			}
		}

		if (platform == "WINDOWS") {
			response = apiClient.listWindowsAuthRecord("Jenkins_Windows_" + this.job_name);
			if (response.getResponseCode() == 200) {
				Document result = response.getResponseXml();
				String recordId = null;
				NodeList authRecords = result.getElementsByTagName("AUTH_WINDOWS");
				for (int i = 0; i < authRecords.getLength(); i++) {
					Node record = authRecords.item(i);
					Element rElement = (Element) record;
					String title = rElement.getElementsByTagName("TITLE").item(0).getTextContent().trim();
					if (title.matches("Jenkins_Windows_" + this.job_name)) {
						recordId = rElement.getElementsByTagName("ID").item(0).getTextContent().trim();
						break;
					}
				}
				if (recordId != null) {
					buildLogger.println(new Timestamp(System.currentTimeMillis())
							+ " Windows Authentication Record Jenkins_Windows_" + this.job_name + " already exists.");
					return result.getElementsByTagName("ID").item(0).getTextContent().trim();
				} else {
					buildLogger.println(new Timestamp(System.currentTimeMillis())
							+ " Windows Authentication Record Jenkins_Windows_" + this.job_name + " is not present.");
					return null;
				}
			} else {
				throw new BuildFailedException(
						"Failed to list Windows Authentication Record Name: Jenkins_Windows_" + this.job_name);
			}
		}

		return null;
	}

	private String isAssetGroupPresent() throws Exception {
		QualysPCResponse response = new QualysPCResponse();
		String assetId = null;
		String apiParams = "&title=Jenkins_AG_" + this.job_name + "&show_attributes=ID";
		response = apiClient.listAssetGroup(apiParams);
		if (response.getResponseCode() == 200) {
			Document result = response.getResponseXml();
			try {
				assetId = result.getElementsByTagName("ID").item(0).getTextContent().trim();
			} catch (Exception e) {
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Asset Group with Name: Jenkins_AG_"
						+ this.job_name + " Not Found");
				return null;
			}
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Asset Group with Name: Jenkins_AG_"
					+ this.job_name + " already exists.");
		} else {
			throw new BuildFailedException("Failed to create asset group for IP: " + this.ipAddress);
		}
		return assetId;
	}

	public boolean updatePoliciesWithAssetGroup() throws Exception {
		buildLogger
				.println(new Timestamp(System.currentTimeMillis()) + " Updating selected policies with asset group...");
		QualysPCResponse response = new QualysPCResponse();
		String msg = "";
		String apiParams = "&asset_group_ids=" + this.assetGroupId;

		for (int i = 0; i < selectedPoliciesJson.length(); i++) {
			String params = apiParams + "&id=" + selectedPoliciesJson.names().getString(i);
			response = apiClient.updatePolicies(params);
			if (response.getResponseCode() == 200) {
				Document result = response.getResponseXml();
				msg = result.getElementsByTagName("TEXT").item(0).getTextContent().trim();
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Policy Name: "
						+ selectedPoliciesJson.get(selectedPoliciesJson.names().getString(i)) + " : " + msg);
			} else {
				throw new BuildFailedException("Failed to update Policy: "
						+ selectedPoliciesJson.get(selectedPoliciesJson.names().getString(i))
						+ " With asset group: Jenkins_AG_" + this.job_name);
			}
		}
		return true;

	}

	public boolean addAssetGroup() throws Exception {
		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Creating Asset group...");
		QualysPCResponse response = new QualysPCResponse();
		String msg = "";
		this.assetGroupId = isAssetGroupPresent();
		if (this.assetGroupId == null) {
			response = apiClient.createAssetGroup(this.job_name, this.ipAddress);
			if (response.getResponseCode() == 200) {
				Document result = response.getResponseXml();
				msg = result.getElementsByTagName("TEXT").item(0).getTextContent().trim();
				this.assetGroupId = result.getElementsByTagName("VALUE").item(0).getTextContent().trim();
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Asset Group for IP " + this.ipAddress
						+ ". " + msg);
			} else {
				throw new BuildFailedException("Failed to create asset group for IP: " + this.ipAddress);
			}
		} else {
			response = apiClient.updateAssetGroup(this.assetGroupId, this.ipAddress);
			if (response.getResponseCode() == 200) {
				Document result = response.getResponseXml();
				msg = result.getElementsByTagName("TEXT").item(0).getTextContent().trim();
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Asset Group for IP " + this.ipAddress
						+ ". " + msg);
			} else {
				throw new BuildFailedException("Failed to update asset group for IP: " + this.ipAddress);
			}
		}
		return true;
	}

	public boolean addAuthRecord() throws Exception {
		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Creating Auth record...");
		QualysPCResponse response = new QualysPCResponse();
		String msg = "";
		if (this.unixAndWindowsCredentialsId == "" || this.unixAndWindowsCredentialsId == null) {
			throw new BuildFailedException(
					"Creating  Authentication record failed. Please provide credentials for windows or unix.");
		}
		ArrayList<String> cred = Helper.getCredentails(unixAndWindowsCredentialsId, run.getParent());
		String apiParams = "&ips=" + this.ipAddress + "&";
		if (cred != null && !cred.isEmpty()) {
			String pass = URLEncoder.encode(cred.get(1), StandardCharsets.UTF_8.toString());
			apiParams = apiParams + "username=" + cred.get(0) + "&password=" + pass;
		}
		if (this.unixAndWindowsCredentials.matches("unix")) {
			this.authRecord = "Jenkins_Unix_" + this.job_name;
			String recordId = isAuthRecordPresent("UNIX");
			if (recordId == null) {
				response = apiClient.createUnixAuthRecord(apiParams, this.job_name);
				if (response.getResponseCode() == 200) {
					Document result = response.getResponseXml();
					msg = result.getElementsByTagName("TEXT").item(0).getTextContent().trim();

					if (!msg.contains("Successfully Created")) {
						throw new BuildFailedException("Failed to create Unix Authentication Record for IP: "
								+ this.ipAddress + ". Error: " + msg);
					} else {
						buildLogger.println(new Timestamp(System.currentTimeMillis())
								+ " Unix Authentication Record for IP " + this.ipAddress + ". " + msg);
					}
				} else {
					throw new BuildFailedException(
							"Failed to create Unix Authentication Record for IP: " + this.ipAddress);
				}
			} else {
				response = apiClient.updateUnixAuthRecord(apiParams, recordId);
				if (response.getResponseCode() == 200) {
					Document result = response.getResponseXml();
					msg = result.getElementsByTagName("TEXT").item(0).getTextContent().trim();

					if (msg.contains("Successfully Updated") || msg.contains("nothing to change")) {
						buildLogger.println(new Timestamp(System.currentTimeMillis())
								+ " Unix Authentication Record for IP " + this.ipAddress + ". " + msg);
					} else {
						throw new BuildFailedException("Failed to update Unix Authentication Record for IP: "
								+ this.ipAddress + ". Error: " + msg);
					}
				} else {
					throw new BuildFailedException(
							"Failed to update Unix Authentication Record for IP: " + this.ipAddress);
				}
			}
		}

		if (this.unixAndWindowsCredentials.matches("windows")) {
			this.authRecord = "Jenkins_Windows_" + this.job_name;
			String recordId = isAuthRecordPresent("WINDOWS");
			if (recordId == null) {
				response = apiClient.createWindowsAuthRecord(apiParams, job_name);
				if (response.getResponseCode() == 200) {
					Document result = response.getResponseXml();
					msg = result.getElementsByTagName("TEXT").item(0).getTextContent().trim();

					if (!msg.contains("Successfully Created")) {
						throw new BuildFailedException("Failed to create Windows Authentication Record for IP: "
								+ this.ipAddress + ". Error: " + msg);
					} else {
						buildLogger.println(new Timestamp(System.currentTimeMillis())
								+ " Windows Authentication Record for IP " + this.ipAddress + ". " + msg);
					}
				} else {
					throw new BuildFailedException(
							"Failed to create Windows Authentication Record for IP: " + this.ipAddress);
				}

			} else {
				response = apiClient.updateWindowsAuthRecord(apiParams, recordId);
				if (response.getResponseCode() == 200) {
					Document result = response.getResponseXml();
					msg = result.getElementsByTagName("TEXT").item(0).getTextContent().trim();

					if (msg.contains("Successfully Updated") || msg.contains("nothing to change")) {
						buildLogger.println(new Timestamp(System.currentTimeMillis())
								+ " Windows Authentication Record for IP " + this.ipAddress + ". " + msg);
					} else {
						throw new BuildFailedException("Failed to update Windows Authentication Record for IP: "
								+ this.ipAddress + ". Error: " + msg);
					}
				} else {
					throw new BuildFailedException(
							"Failed to update Windows Authentication Record for IP: " + this.ipAddress);
				}
			}
		}
		return true;
	}

	public boolean addHost() throws Exception {
		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Adding Host into User Account...");
		QualysPCResponse response = new QualysPCResponse();
		String msg = "";

		if (useHost) {
			response = apiClient.addHost(hostIp);
			this.ipAddress = hostIp;
			msg = "Host IP: " + hostIp + ".";
		}

		if (useEc2) {
			response = apiClient.addHost(ec2PrivateIpAddress);
			this.ipAddress = ec2PrivateIpAddress;
			msg = "Host IP: " + ec2PrivateIpAddress + ".";
		}
		if (response.getResponseCode() == 200) {
			Document result = response.getResponseXml();
			msg = msg + " " + result.getElementsByTagName("TEXT").item(0).getTextContent().trim();
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + msg);
			return true;
		} else {
			throw new BuildFailedException("Failed to add " + msg + " in user account.");
		}
	}

	/* This method is called in getAndProcessLaunchScanResult */
	public Map<String, String> launchScan() throws Exception {
		String requestData = new String();
		String printLine = " Calling Launch Scan API with Payload: ";
		Document result = null;
		StringBuilder vmScan = new StringBuilder();
		Map<String, String> returnMap = new HashMap<String, String>();
		EnvVars env = run.getEnvironment(listener);
		String build_no = env.get("BUILD_NUMBER");
		String timestamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss").format(new Date());
		this.scanNameResolved = this.scanName.replaceAll("(?i)\\[job_name\\]", this.job_name)
				.replaceAll("(?i)\\[build_number\\]", build_no).replaceAll("(?i)\\[timestamp\\]", timestamp);

		if (this.scanNameResolved == null || this.scanNameResolved.isEmpty()) {
			throw new AbortException("Scan Name - Required parameter to launch scan is missing.");
		} else {
			vmScan.append(String.format("%s=%s&", "scan_title", Helper.urlEncodeUTF8(this.scanNameResolved.trim())));
		}

		if (optionProfile != null && !optionProfile.isEmpty()) {
			vmScan.append(String.format("%s=%s&", "option_title", Helper.urlEncodeUTF8(optionProfile)));
		} else {
			throw new AbortException("Option Profile - Required parameter to launch scan is missing.");
		}

		if (scannerName != null && !scannerName.isEmpty()) {
			vmScan.append(String.format("%s=%s&", "iscanner_name", Helper.urlEncodeUTF8(scannerName)));
		} else {
			throw new AbortException("Scanner Name - Required parameter to launch scan is missing.");
		}

		if (useHost) {
			if (hostIp != null && !hostIp.isEmpty()) {
				vmScan.append(String.format("%s=%s&", "ip", Helper.urlEncodeUTF8(hostIp)));
			} else {
				throw new AbortException("Host IP - Required parameter to launch scan is missing.");
			}
		}

		if (useEc2) {
			if (ec2Id != null && !ec2Id.isEmpty()) {
				vmScan.append(String.format("%s=%s&", "ec2_instance_ids", Helper.urlEncodeUTF8(ec2Id)));
			} else {
				throw new AbortException("EC2 Instance ID - Required parameter to launch scan is missing.");
			}
			if (ec2ConnName != null && !ec2ConnName.isEmpty()) {
				vmScan.append(String.format("%s=%s&", "connector_name", Helper.urlEncodeUTF8(ec2ConnName)));
			} else {
				throw new AbortException("EC2 Connector Name - Required parameter to launch scan is missing.");
			}
			if (ec2Endpoint != null && !ec2Endpoint.isEmpty()) {
				vmScan.append(String.format("%s=%s&", "ec2_endpoint", Helper.urlEncodeUTF8(ec2Endpoint)));
			} else {
				throw new AbortException("EC2 Endpoint - Required parameter to launch scan is missing.");
			}
		}

		try {
			requestData = vmScan.toString();
			requestData = requestData.substring(0, requestData.length() - 1);
			logger.info(printLine + requestData);

			if (this.failByStateAndCriticality || this.failByAuth || this.excludedCriteria) {
				String criteria = "";
				if (this.failByStateAndCriticality) {
					criteria = "Fail by State AND Criticality: " + this.getFailureConditionMsg();
				}
				criteria = criteria + " Fail by Authentication Failure: " + this.failByAuth + ".";
				if (this.excludedCriteria) {
					criteria = criteria + " Exclusion Criteria By CIDs: " + this.excludedCids + ".";
				}
				buildLogger
						.println(new Timestamp(System.currentTimeMillis()) + " Build failure conditions: " + criteria);
				logger.info("Build failure conditions: " + criteria);
			} else {
				buildLogger
						.println(new Timestamp(System.currentTimeMillis()) + " No failure conditions configuration.");
				logger.info("No failure conditions configuration.");
			}

			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Launching scan now...");
			QualysPCResponse response = apiClient.launchPcScan(requestData);
			if (response.getRequestBody() != null)
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " API POST request body: "
						+ response.getRequestBody());
			result = response.getResponseXml();
			Integer respCodeObj = response.getResponseCode();

			if (respCodeObj == null || respCodeObj != 200) {
				String error = response.getErrorMessage().toString();
				logger.info("Server Response: " + error + ". Please do retry after sometime.");
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Server Response: " + error
						+ ". Please do retry after sometime.");
				throw new AbortException("Error while launching new scan. Server returned: " + error
						+ ". Please do retry after sometime.");
			} else {
				try {
					if (result.getDocumentElement().getNodeName().equalsIgnoreCase("SIMPLE_RETURN")) {
						NodeList error = result.getElementsByTagName("RESPONSE");
						for (int temp = 0; temp < error.getLength(); temp++) {
							Node nNode = error.item(temp);
							if (nNode.getNodeType() == Node.ELEMENT_NODE) {
								Element eElement = (Element) nNode;
								if (eElement.getElementsByTagName("CODE").getLength() != 0) {
									returnMap.put("errorCode",
											eElement.getElementsByTagName("CODE").item(0).getTextContent().trim());
								} else {
									returnMap.put("errorCode", null);
								}
								if (eElement.getElementsByTagName("TEXT").getLength() != 0) {
									returnMap.put("errorText",
											eElement.getElementsByTagName("TEXT").item(0).getTextContent().trim());
								} else {
									returnMap.put("errorText", null);
								}
							}
						}
						NodeList applinaceList = result.getElementsByTagName("ITEM");
						for (int temp = 0; temp < applinaceList.getLength(); temp++) {
							Node nNode = applinaceList.item(temp);
							if (nNode.getNodeType() == Node.ELEMENT_NODE) {
								Element eElement = (Element) nNode;
								String key = eElement.getElementsByTagName("KEY").item(0).getTextContent();
								if (key.equalsIgnoreCase("REFERENCE")) {
									returnMap.put("scanRef",
											eElement.getElementsByTagName("VALUE").item(0).getTextContent().trim());
								} // End of Inner if
								if (key.equalsIgnoreCase("ID")) {
									returnMap.put("scanId",
											eElement.getElementsByTagName("VALUE").item(0).getTextContent().trim());
								} // End of Inner if
							} // End of Outer if
						} // End of for loop
					} else if (result.getDocumentElement().getNodeName().equalsIgnoreCase("GENERIC_RETURN")) {
						NodeList error = result.getElementsByTagName("GENERIC_RETURN");
						for (int temp = 0; temp < error.getLength(); temp++) {
							Node nNode = error.item(temp);
							if (nNode.getNodeType() == Node.ELEMENT_NODE) {
								Element eElement = (Element) nNode;
								if (eElement.getElementsByTagName("RETURN").getLength() != 0) {
									returnMap.put("errorText",
											eElement.getElementsByTagName("RETURN").item(0).getTextContent().trim());
								} else {
									returnMap.put("errorText", null);
								}
								NodeList e = eElement.getElementsByTagName("RETURN");
								for (int t = 0; t < e.getLength(); t++) {
									Node n = e.item(t);
									if (n.getNodeType() == Node.ELEMENT_NODE) {
										Element ee = (Element) n;
										if (!ee.getAttribute("number").isEmpty()) {
											returnMap.put("errorCode", ee.getAttribute("number"));
										} else {
											returnMap.put("errorCode", null);
										}
									}
								}
							}
						}
					}
					return returnMap;
				} catch (Exception e) {
					throw e;
				}
			} // end of else
		} catch (AbortException e) {
			throw new AbortException("Process Aborted.");
		} catch (Exception e) {
			logger.info("Exception while launching scan. Error: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			throw e;
		} // end of catch
	} // End of LaunchScan method

}// end of PCScanLauncher class