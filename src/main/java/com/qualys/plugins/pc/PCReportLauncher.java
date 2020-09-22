package com.qualys.plugins.pc;

import java.io.PrintStream;
import java.sql.Timestamp;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import org.kohsuke.stapler.DataBoundConstructor;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.qualys.plugins.pc.util.Helper;
import com.qualys.plugins.pc.util.TimeOutException;
import com.qualys.plugins.pc.auth.QualysAuth;
import com.qualys.plugins.pc.client.QualysPCClient;
import com.qualys.plugins.pc.client.QualysPCResponse;

import hudson.model.Run;
import hudson.model.TaskListener;

public class PCReportLauncher extends Thread {

	private Run<?, ?> run;
	private PrintStream buildLogger;
	private int pollingIntervalForVulns;
	private QualysPCClient apiClient;
	private String policy_id;
	private String excludedCids;
	private boolean criticalityMinimal;
	private boolean criticalityMedium;
	private boolean criticalityCritical;
	private boolean criticalityUrgent;
	private boolean criticalitySerious;
	private boolean stateError;
	private boolean stateFail;
	public String policyName;
	private boolean stateExceptions;
	private String assetGroupId;
	private boolean failByStateAndCriticality;
	private boolean excludedCriteria;
	private int totalControlFailCount = -1;
	private String ipAddress;
	public boolean controlFail = false;
	private final static Logger logger = Helper.getLogger(PCReportLauncher.class.getName());

	public boolean getControlFail() {
		return controlFail;
	}

	public int getFailControlCount() {
		return this.totalControlFailCount;
	}

	@DataBoundConstructor
	public PCReportLauncher(Run<?, ?> run, TaskListener listener, String ec2Id, String ec2ConnName, String ec2Endpoint,
			boolean useHost, boolean useEc2, QualysAuth auth, String policy_id, String policyName,
			int pollingIntervalForVulns, QualysPCClient apiClient, String ipAddress, boolean stateFail,
			boolean stateError, boolean stateExceptions, boolean criticalitySerious, boolean criticalityUrgent,
			boolean criticalityCritical, boolean criticalityMedium, boolean criticalityMinimal, boolean failByAuth,
			String excludedCids, String assetGroupId, boolean failByStateAndCriticality, boolean excludedCriteria) {

		this.run = run;
		this.buildLogger = listener.getLogger();
		this.assetGroupId = assetGroupId;
		this.policy_id = policy_id;
		this.policyName = policyName;
		this.failByStateAndCriticality = failByStateAndCriticality;
		this.ipAddress = ipAddress;

		this.pollingIntervalForVulns = pollingIntervalForVulns;
		this.apiClient = apiClient;

		this.stateFail = stateFail;
		this.stateError = stateError;
		this.stateExceptions = stateExceptions;

		this.criticalitySerious = criticalitySerious;
		this.criticalityUrgent = criticalityUrgent;
		this.criticalityCritical = criticalityCritical;
		this.criticalityMedium = criticalityMedium;
		this.criticalityMinimal = criticalityMinimal;

		this.excludedCids = excludedCids;
		this.excludedCriteria = excludedCriteria;

	} // End of Constructor

	public void run() {
		try {
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Started new thread ("
					+ Thread.currentThread().getId() + ") for policy Id:" + this.policy_id);

			this.controlFail = getAndEvaluateResult();
		} catch (Exception e) {
			logger.info("Thread :" + Thread.currentThread().getId()
					+ "Exception while fetching and evaluating result. Error: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
		}
	}

	private boolean getAndEvaluateResult() throws TimeOutException, Exception {
		JsonArray failedCountrols = new JsonArray();
		JsonObject scanResult = null;
		Gson gson = new Gson();

		// Waiting for data
		logger.info("Waiting for a minute before fetching the posture data for the host");
		Thread.sleep(60000);

		// Polling if data is not ready for policy
		int pollingMaxCount = 3;
		int pollingCount = 0;
		long pollingInMillis = TimeUnit.MINUTES.toMillis(pollingIntervalForVulns);
		try {
			while ((scanResult = getReportData()) == null) {
				if (pollingCount >= pollingMaxCount) {
					String error = " Error: No data found for policy \"" + this.policyName + "\" and host "
							+ this.ipAddress;
					buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
					logger.info(error);
					return true;
				}
				buildLogger
						.println(new Timestamp(System.currentTimeMillis()) + " Waiting for " + pollingIntervalForVulns
								+ " minute(s) before making next attempt for policy Id:" + this.policy_id);
				pollingCount += 1;
				Thread.sleep(pollingInMillis);
			}
		} catch (Exception e) {
			String error = " Exception: Failed to get policy data. " + e.getMessage();
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
			logger.info(error);
			throw e;
		}
		if (this.failByStateAndCriticality) {
			failedCountrols = evaluateFailuerCriteria(scanResult);
		}
		scanResult.addProperty("controlFailCount", failedCountrols.size());
		scanResult.add("failedCountrols", failedCountrols);
		scanResult.addProperty("policyId", this.policy_id);
		scanResult.addProperty("policyName", this.policyName);

		this.totalControlFailCount = failedCountrols.size();
		if (scanResult != null) {
			String scanResultString = gson.toJson(scanResult);
			Helper.createNewFile(run.getArtifactsDir().getAbsolutePath(), "qualys_" + this.policy_id, scanResultString,
					buildLogger);
		}
		if (failedCountrols.size() > 0) {
			return true;
		} else {
			return false;
		}
	}

	private JsonObject getControlData(Document result) throws Exception {
		NodeList reportResults = result.getElementsByTagName("INFO");
		JsonObject controlList = new JsonObject();
		for (int temp = 0; temp < reportResults.getLength(); temp++) {
			Node nNode = reportResults.item(temp);
			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
				Element eElement = (Element) nNode;
				JsonObject scanResult = new JsonObject();
				// CID
				String cid = eElement.getElementsByTagName("CONTROL_ID").item(0).getTextContent().trim();

				// STATUS
				String status = eElement.getElementsByTagName("STATUS").item(0).getTextContent().trim();
				scanResult.addProperty("status", status);
				if (status.matches("Failed")) {
					String missingValues = "";
					String unexpectedValues = "";

					NodeList causeOfFailures = eElement.getElementsByTagName("CAUSE_OF_FAILURE");
					Node causeOfFailure = causeOfFailures.item(0);
					Element causeOfFailureValue = (Element) causeOfFailure;

					NodeList causeOfFailureUnexpecteds = causeOfFailureValue.getElementsByTagName("UNEXPECTED");
					if (causeOfFailureUnexpecteds.getLength() > 0) {
						Node causeOfFailureUnexpected = causeOfFailureUnexpecteds.item(0);
						Element causeOfFailureUnexpectedValue = (Element) causeOfFailureUnexpected;

						NodeList causeOfFailureUnexpectedValues = causeOfFailureUnexpectedValue
								.getElementsByTagName("V");

						for (int i = 0; i < causeOfFailureUnexpectedValues.getLength(); i++) {
							unexpectedValues = unexpectedValues + causeOfFailureUnexpectedValue
									.getElementsByTagName("V").item(i).getTextContent().trim() + ", ";
						}
					}

					NodeList causeOfFailureMissing = causeOfFailureValue.getElementsByTagName("MISSING");
					if (causeOfFailureMissing.getLength() > 0) {
						Node causeOfFailureMissingNode = causeOfFailureMissing.item(0);
						Element causeOfFailureMissingValues = (Element) causeOfFailureMissingNode;

						NodeList causeOfFailureMissingValuesList = causeOfFailureMissingValues
								.getElementsByTagName("V");

						for (int i = 0; i < causeOfFailureMissingValuesList.getLength(); i++) {
							missingValues = missingValues + causeOfFailureMissingValues.getElementsByTagName("V")
									.item(i).getTextContent().trim() + ", ";
						}
					}

					scanResult.addProperty("unexpected_values", unexpectedValues);
					scanResult.addProperty("missing_values", missingValues);
				} else {
					scanResult.addProperty("unexpected_values", "N/A");
					scanResult.addProperty("missing_values", "N/A");
				}
				controlList.add(cid, scanResult);
			}
		}

		reportResults = result.getElementsByTagName("CONTROL");
		for (int temp = 0; temp < reportResults.getLength(); temp++) {
			Node nNode = reportResults.item(temp);
			if (nNode.getNodeType() == Node.ELEMENT_NODE) {
				Element eElement = (Element) nNode;

				// CID
				String cid = eElement.getElementsByTagName("ID").item(0).getTextContent().trim();
				// scanResult.addProperty("cid", cid);
				JsonObject scanResult = (JsonObject) controlList.get(cid);
				// STATEMENT
				String statement = eElement.getElementsByTagName("STATEMENT").item(0).getTextContent().trim();
				scanResult.addProperty("statement", statement);
				// CRITICALITY
				NodeList criticality = eElement.getElementsByTagName("CRITICALITY");
				Node criticalityLabel = criticality.item(0);
				Element lElement = (Element) criticalityLabel;
				String label = lElement.getElementsByTagName("LABEL").item(0).getTextContent().trim();
				scanResult.addProperty("criticality", label);

				controlList.add(cid, scanResult);
			}
		}
		return controlList;
	}

	private JsonArray evaluateFailuerCriteria(JsonObject reportResult) throws Exception {
		JsonObject control = (JsonObject) reportResult.get("controls");
		boolean criticalityFail = false;
		boolean countrolFail = false;
		JsonArray failedCountrols = new JsonArray();

		for (Iterator iterator = control.keySet().iterator(); iterator.hasNext();) {
			String cid = (String) iterator.next();

			JsonObject element = (JsonObject) control.get(cid);
			criticalityFail = false;
			countrolFail = false;

			String criticality = element.get("criticality").getAsString();
			String status = element.get("status").getAsString();

			if (this.excludedCriteria && this.excludedCids.contains(cid)) {
				continue;
			}

			if ((criticality.matches("MEDIUM") && this.criticalityMedium)
					|| (criticality.matches("SERIOUS") && this.criticalitySerious)
					|| (criticality.matches("URGENT") && this.criticalityUrgent)
					|| (criticality.matches("CRITICAL") && this.criticalityCritical)
					|| (criticality.matches("MINIMAL") && this.criticalityMinimal)) {
				criticalityFail = true;
			}

			if (((status.matches("Exceptions") && this.stateExceptions) || (status.matches("Failed") && this.stateFail)
					|| (status.matches("Error") && this.stateError)) && criticalityFail) {
				countrolFail = true;
			}
			if (countrolFail) {
				failedCountrols.add(cid);
			}

		}

		return failedCountrols;
	}

	private JsonObject getReportData() throws Exception {
		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Fetching report result..");
		JsonObject scanResult = new JsonObject();
		String apiParams = "&policy_id=" + this.policy_id + "&output_format=xml&details=Basic&cause_of_failure=1";
		apiParams = apiParams + "&asset_group_ids=" + this.assetGroupId;
		QualysPCResponse statusResponse = apiClient.getReportResult(apiParams);

		try {
			Document result = null;
			result = statusResponse.getResponseXml();
			NodeList reportResults = result.getElementsByTagName("SUMMARY");
			Node reportResult = reportResults.item(0);

			Element eElement = (Element) reportResult;
			if (eElement.getElementsByTagName("TOTAL_PASSED").getLength() != 0) {
				String total_passed = eElement.getElementsByTagName("TOTAL_PASSED").item(0).getTextContent().trim();
				scanResult.addProperty("total_passed", total_passed);
			}

			if (eElement.getElementsByTagName("TOTAL_FAILED").getLength() != 0) {
				String total_failed = eElement.getElementsByTagName("TOTAL_FAILED").item(0).getTextContent().trim();
				scanResult.addProperty("total_failed", total_failed);
			}

			if (eElement.getElementsByTagName("TOTAL_ERROR").getLength() != 0) {
				String total_error = eElement.getElementsByTagName("TOTAL_ERROR").item(0).getTextContent().trim();
				scanResult.addProperty("total_error", total_error);
			}

			if (eElement.getElementsByTagName("TOTAL_EXCEPTIONS").getLength() != 0) {
				String total_exceptions = eElement.getElementsByTagName("TOTAL_EXCEPTIONS").item(0).getTextContent()
						.trim();
				scanResult.addProperty("total_exceptions", total_exceptions);
			}

			scanResult.add("controls", getControlData(result));
		} catch (Exception e) {
			String error = "Data not found for policy \"" + this.policyName + "\" and host " + this.ipAddress;
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + error);
			logger.info(error + e.getMessage());
			return null;
		}

		return scanResult;
	}// end of getScanResult

} // End of PCReportLauncher class
