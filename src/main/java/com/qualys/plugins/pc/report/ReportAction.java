package com.qualys.plugins.pc.report;

import java.io.File;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;
import org.kohsuke.stapler.bind.JavaScriptMethod;
import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;
import com.qualys.plugins.pc.util.Helper;

import hudson.Extension;
import hudson.model.Action;
import hudson.model.Run;
import hudson.util.Secret;
import net.sf.json.JSONObject;

@Extension
public class ReportAction implements Action {
	private String scanId;
	private String scanRef;
	private String excludedCids;
	private String scanName;
	private String scanTarget;
	private Run<?, ?> run;
	private boolean buildStatus;
	private String ipAddress;
	private String scanStatustUrl;
	private String platformUrl;
	private String scanDuration;
	private String scanLaunchDate;
	private String authRecord;
	private JSONObject scanResult;
	private List<String> policyIds;
	private List<String> policyNames;
	private boolean excludedCriteria;
	private String failCriteria;

	private final static Logger logger = Helper.getLogger(ReportAction.class.getName());

	public ReportAction() {
	}

	public ReportAction(Run<?, ?> run, String scanId, String scanName, String scanRef, String scanDuration,
			String scanLaunchDate, String authRecord, String ipAddress, String apiServer, String platformUrl,
			String apiUser, Secret apiPass, boolean useProxy, String proxyServer, int proxyPort, String proxyUsername,
			Secret proxyPassword, boolean buildStatus, List<String> policyIds, List<String> policyNames,
			String excludedCids, boolean excludedCriteria, String failCriteria) {

		this.ipAddress = ipAddress;
		this.buildStatus = buildStatus;
		this.scanDuration = scanDuration;
		this.scanLaunchDate = scanLaunchDate;
		this.policyIds = policyIds;
		this.policyNames = policyNames;
		this.excludedCids = excludedCids;
		this.excludedCriteria = excludedCriteria;
		this.failCriteria = failCriteria;

		this.scanId = scanId;
		this.scanRef = scanRef;
		this.scanName = scanName;
		this.platformUrl = platformUrl;
		this.authRecord = authRecord;
		this.scanTarget = ipAddress;

		this.scanStatustUrl = "/fo/report/compliance_scan_result.php?id=" + scanId;
		this.run = run;
	}

	public String getScanId() {
		return this.scanId;
	}

	public String getExcludedControls() {
		if (this.excludedCriteria) {
			return this.excludedCids;
		} else {
			return "";
		}
	}

	public String getPolicyList() {
		String strPolicy = "";
		for (String policy : policyNames) {
			strPolicy = strPolicy + "\"" + policy + "\",";
		}
		strPolicy = strPolicy.substring(0, strPolicy.length() - 1);
		return strPolicy;
	}

	public List<JSONObject> getControlsList() {
		List<JSONObject> controlList = new ArrayList<JSONObject>();
		for (int i = 0; i < scanResult.size(); i++) {
			String policyName = scanResult.names().getString(i);
			JSONObject policyValue = (JSONObject) scanResult.get(policyName);
			JSONObject pValue = new JSONObject();
			pValue = (JSONObject) policyValue.get("controls");
			for (int j = 0; j < pValue.size(); j++) {
				JSONObject control = new JSONObject();
				String cId = pValue.names().getString(j);
				JSONObject cValue = (JSONObject) pValue.get(cId);

				control.put("pName", policyName);
				control.put("cid", cId);
				control.put("status", cValue.get("status"));
				control.put("statement", cValue.get("statement"));
				control.put("criticality", cValue.get("criticality"));
				control.put("unexpected_values", cValue.get("unexpected_values"));
				control.put("missing_values", cValue.get("missing_values"));
				controlList.add(control);
			}
		}
		return controlList;
	}

	public String getAuthRecord() {
		if (this.authRecord != null) {
			return this.authRecord;
		} else {
			return "-";
		}
	}

	public String getScanRef() {
		return this.scanRef;
	}

	public String getScanTarget() {
		return this.ipAddress;
	}

	public String getScanName() {
		return this.scanName;
	}

	public String getScanDuration() {
		return this.scanDuration;
	}

	public String getScanLaunchDate() {
		return this.scanLaunchDate;
	}

	public String getScanStatusUrl() {
		return this.platformUrl + this.scanStatustUrl;
	}

	public String getFailCriteria() {
		return failCriteria;
	}

	public String getBuildStatus() {
		if (this.buildStatus) {
			return "FAILED";
		} else {
			return "PASSED";
		}
	}

	@JavaScriptMethod
	public JSONObject getScanResults() {
		JSONObject result = new JSONObject();
		this.scanResult = new JSONObject();
		if (this.policyIds != null) {
			for (String policy : this.policyIds) {
				JSONObject respObj = null;
				try {
					String filename = run.getArtifactsDir().getAbsolutePath() + File.separator + "qualys_" + policy
							+ ".json";
					File f = new File(filename);
					Gson gson = new Gson();
					if (f.exists()) {
						String resultStr = FileUtils.readFileToString(f);
						String resultStrClean = resultStr;
						JsonReader jr = new JsonReader(new StringReader(resultStrClean.trim()));
						jr.setLenient(true);
						respObj = gson.fromJson(jr, JSONObject.class);
						int pos = this.policyIds.indexOf(policy);
						result.put(this.policyNames.get(pos), respObj);
					}
				} catch (Exception e) {
					logger.info("Error parsing scan Result for policy: " + e.getMessage());
					scanResult.put("error", e.getMessage());
				}
			}
		}
		scanResult = result;
		return scanResult;
	}

	@Override
	public String getIconFileName() {
		return "/plugin/qualys-pc/images/tinyLogo.png";
	}

	@Override
	public String getDisplayName() {
		return "Qualys PC Scan Report for " + this.scanTarget.toString();
	}

	@Override
	public String getUrlName() {
		return "qualys_pc_scan_report_" + this.scanTarget.toString() + ".html";
	}
}