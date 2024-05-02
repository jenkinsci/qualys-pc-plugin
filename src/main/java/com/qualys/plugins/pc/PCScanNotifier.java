package com.qualys.plugins.pc;

import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Map;
import hudson.EnvVars;

import javax.annotation.Nonnull;
import javax.servlet.ServletException;

import org.apache.commons.lang.StringUtils;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.jenkinsci.Symbol;
import org.json.JSONObject;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qualys.plugins.pc.util.Helper;
import com.qualys.plugins.pc.auth.QualysAuth;
import com.qualys.plugins.pc.client.QualysPCClient;
import com.qualys.plugins.pc.client.QualysPCResponse;

import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;

public class PCScanNotifier extends Notifier implements SimpleBuildStep {

	private String apiServer;
	private String credsId;
	private String hostIp;
	private String ec2Id;
	private String ec2ConnDetails;
	private String ec2ConnName;
	private String ec2ConnAccountId;
	private String ec2ConnId;
	private String scanName;
	private String scannerName;
	private String optionProfile;
	private String proxyServer;
	private int proxyPort;
	private String proxyCredentialsId;
	private boolean useProxy = false;
	private boolean useHost = false;
	private boolean useEc2 = false;
	private boolean runConnector = false;
	private String pluginName = "Qualys PC Scanning Connector";
	private String pollingInterval;
	private String vulnsTimeout;
	private String selectedPolicies;
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
	private String optionProfileName;
	private String unixAndWindowsCredentialsId;
	private boolean createAuthRecord = false;
	private JSONObject selectedPoliciesJson;
	private String unixAndWindowsCredentials;
	private boolean failByStateAndCriticality;
	private boolean excludedCriteria;
	private String platform;
	private String hostIpValue;
	private String ec2IdValue;

	private final static String SCAN_NAME = "[job_name]_jenkins_build_[build_number]";
	private final static int PROXY_PORT = 80;
	private static QualysPCResponse optionProfileRawData;

	private final static Logger logger = Helper.getLogger(PCScanNotifier.class.getName());
	/* End of Variable Declaration */

	public PCScanNotifier() {
	}

	public String getCredsId() {
		return credsId;
	}

	@DataBoundSetter
	public void setCredsId(String cred) {
		this.credsId = cred;
	}

	/* Getter Setters */

	public String getPollingInterval() {
		return pollingInterval;
	}

	@DataBoundSetter
	public void setPollingInterval(String pollingInterval) {
		this.pollingInterval = pollingInterval;
	}

	public String getVulnsTimeout() {
		return vulnsTimeout;
	}

	@DataBoundSetter
	public void setVulnsTimeout(String vulnsTimeout) {
		this.vulnsTimeout = vulnsTimeout;
	}

	public String getApiServer() {
		return apiServer;
	}

	@DataBoundSetter
	public void setApiServer(String apiServer) {
		if (apiServer != null && apiServer.endsWith("/")) {
			apiServer = apiServer.substring(0, apiServer.length() - 1);
		}
		this.apiServer = apiServer;
	}

	public String getHostIp() {
		return hostIp;
	}

	@DataBoundSetter
	public void setHostIp(String hostIp) {
		this.hostIp = hostIp;
	}

	public String getEc2Id() {
		return ec2Id;
	}

	@DataBoundSetter
	public void setEc2Id(String ec2Id) {
		this.ec2Id = ec2Id;
	}

	public String getEc2ConnDetails() {
		return ec2ConnDetails;
	}

	@DataBoundSetter
	public void setEc2ConnDetails(String ec2ConnDetails) {
		this.ec2ConnDetails = ec2ConnDetails;
	}

	public String getEc2ConnName() {
		return ec2ConnName;
	}

	@DataBoundSetter
	public void setEc2ConnName(String ec2ConnName) {
		this.ec2ConnName = ec2ConnName;
	}

	public String getEc2ConnAccountId() {
		return ec2ConnAccountId;
	}

	@DataBoundSetter
	public void setEc2ConnAccountId(String ec2ConnAccountId) {
		this.ec2ConnAccountId = ec2ConnAccountId;
	}

	public String getEc2ConnId() {
		return ec2ConnId;
	}

	@DataBoundSetter
	public void setEc2ConnId(String ec2ConnId) {
		this.ec2ConnId = ec2ConnId;
	}

	public boolean getRunConnector() {
		return runConnector;
	}

	@DataBoundSetter
	public void setRunConnector(boolean runConnector) {
		this.runConnector = runConnector;
	}

	public String getScannerName() {
		return scannerName;
	}

	@DataBoundSetter
	public void setScannerName(String scannerName) {
		this.scannerName = scannerName;
	}

	public String getScanName() {
		return scanName;
	}

	@DataBoundSetter
	public void setScanName(String scanName) {
		scanName = StringUtils.isBlank(scanName) ? SCAN_NAME : scanName;
		this.scanName = scanName;
	}

	public String getOptionProfile() {
		return optionProfile;
	}

	@DataBoundSetter
	public void setOptionProfile(String optionProfile) {
		this.optionProfile = optionProfile;
	}

	public String getProxyServer() {
		return proxyServer;
	}

	@DataBoundSetter
	public void setProxyServer(String proxyServer) {
		this.proxyServer = proxyServer;
	}

	public int getProxyPort() {
		return proxyPort;
	}

	@DataBoundSetter
	public void setProxyPort(int proxyPort) {
		proxyPort = proxyPort <= 0 ? PROXY_PORT : proxyPort;
		this.proxyPort = proxyPort;
	}

	public String getProxyCredentialsId() {
		return proxyCredentialsId;
	}

	@DataBoundSetter
	public void setProxyCredentialsId(String proxyCredentialsId) {
		this.proxyCredentialsId = proxyCredentialsId;
	}

	public String getUnixAndWindowsCredentialsId() {
		return unixAndWindowsCredentialsId;
	}

	@DataBoundSetter
	public void setUnixAndWindowsCredentialsId(String unixAndWindowsCredentialsId) {
		this.unixAndWindowsCredentialsId = unixAndWindowsCredentialsId;
	}

	public boolean getUseProxy() {
		return useProxy;
	}

	@DataBoundSetter
	public void setUseProxy(boolean useProxy) {
		this.useProxy = useProxy;
	}

	public boolean getUseHost() {
		return useHost;
	}

	@DataBoundSetter
	public void setUseHost(boolean useHost) {
		this.useHost = useHost;
	}

	public boolean getUseEc2() {
		return useEc2;
	}

	@DataBoundSetter
	public void setUseEc2(boolean useEc2) {
		this.useEc2 = useEc2;
	}

	public boolean getStateFail() {
		return stateFail;
	}

	@DataBoundSetter
	public void setStateFail(boolean stateFail) {
		this.stateFail = stateFail;
	}

	public boolean getStateError() {
		return stateError;
	}

	@DataBoundSetter
	public void setStateError(boolean stateError) {
		this.stateError = stateError;
	}

	public boolean getStateExceptions() {
		return stateExceptions;
	}

	@DataBoundSetter
	public void setStateExceptions(boolean stateExceptions) {
		this.stateExceptions = stateExceptions;
	}

	public boolean getCriticalitySerious() {
		return criticalitySerious;
	}

	@DataBoundSetter
	public void setCriticalitySerious(boolean criticalitySerious) {
		this.criticalitySerious = criticalitySerious;
	}

	public boolean getCriticalityUrgent() {
		return criticalityUrgent;
	}

	@DataBoundSetter
	public void setCriticalityUrgent(boolean criticalityUrgent) {
		this.criticalityUrgent = criticalityUrgent;
	}

	public boolean getCriticalityCritical() {
		return criticalityCritical;
	}

	@DataBoundSetter
	public void setCriticalityCritical(boolean criticalityCritical) {
		this.criticalityCritical = criticalityCritical;
	}

	public boolean getCriticalityMedium() {
		return criticalityMedium;
	}

	@DataBoundSetter
	public void setCriticalityMedium(boolean criticalityMedium) {
		this.criticalityMedium = criticalityMedium;
	}

	public boolean getCriticalityMinimal() {
		return criticalityMinimal;
	}

	@DataBoundSetter
	public void setCriticalityMinimal(boolean criticalityMinimal) {
		this.criticalityMinimal = criticalityMinimal;
	}

	public boolean getFailByAuth() {
		return failByAuth;
	}

	@DataBoundSetter
	public void setFailByAuth(boolean failByAuth) {
		this.failByAuth = failByAuth;
	}

	public String getExcludedCids() {
		return excludedCids;
	}

	@DataBoundSetter
	public void setExcludedCids(String excludedCids) {
		this.excludedCids = excludedCids;
	}

	public String getSelectedPolicies() {
		return selectedPolicies;
	}

	@DataBoundSetter
	public void setSelectedPolicies(String selectedPolicies) {
		this.selectedPolicies = selectedPolicies;
	}

	public boolean getFailByStateAndCriticality() {
		return failByStateAndCriticality;
	}

	@DataBoundSetter
	public void setFailByStateAndCriticality(boolean failByStateAndCriticality) {
		this.failByStateAndCriticality = failByStateAndCriticality;
	}

	public boolean getCreateAuthRecord() {
		return createAuthRecord;
	}

	@DataBoundSetter
	public void setCreateAuthRecord(boolean createAuthRecord) {
		this.createAuthRecord = createAuthRecord;
	}

	public String getUnixAndWindowsCredentials() {
		return unixAndWindowsCredentials;
	}

	@DataBoundSetter
	public void setUnixAndWindowsCredentials(String unixAndWindowsCredentials) {
		this.unixAndWindowsCredentials = unixAndWindowsCredentials;
	}

	public boolean getExcludedCriteria() {
		return excludedCriteria;
	}

	public String getPlatform() {
		return platform;
	}

	@DataBoundSetter
	public void setPlatform(String platform) {
		this.platform = platform;
	}

	@DataBoundSetter
	public void setExcludedCriteria(boolean excludedCriteria) {
		this.excludedCriteria = excludedCriteria;
	}
	/* End of Getter Setters */

	@DataBoundConstructor
	public PCScanNotifier(String apiServer, String credsId, boolean useProxy, boolean createAuthRecord,
			String proxyServer, int proxyPort, String proxyCredentialsId, String unixAndWindowsCredentialsId,
			String scanName, boolean useHost, String hostIp, boolean useEc2, String ec2Id, String ec2ConnDetails,
			boolean runConnector, String optionProfile, String scannerName, String selectedPolicies, boolean stateFail,
			boolean stateError, boolean stateExceptions, boolean criticalitySerious, boolean criticalityUrgent,
			boolean criticalityCritical, boolean criticalityMedium, boolean criticalityMinimal, boolean failByAuth,
			String excludedCids, String pollingInterval, String vulnsTimeout, String unixAndWindowsCredentials,
			boolean failByStateAndCriticality, boolean excludedCriteria, String platform) {

		this.platform = platform;
		if (platform != null && platform.equalsIgnoreCase("pcp")) {
			this.apiServer = apiServer;
		}
		this.credsId = credsId;
		this.scanName = scanName;
		this.optionProfile = optionProfile;
		this.createAuthRecord = createAuthRecord;

		this.failByStateAndCriticality = failByStateAndCriticality;
		this.excludedCriteria = excludedCriteria;

		JsonParser jsonParser = new JsonParser();

		this.scannerName = scannerName;

		if (useProxy) {
			this.useProxy = useProxy;
			this.proxyServer = proxyServer;
			this.proxyPort = proxyPort;
			this.proxyCredentialsId = proxyCredentialsId;
		}

		if (useHost) {
			this.useHost = useHost;
			this.hostIp = hostIp;
		}

		if (useEc2) {
			this.useEc2 = useEc2;
			this.ec2Id = ec2Id;
			this.runConnector = runConnector;
			if (ec2ConnDetails == null || ec2ConnDetails.isEmpty()) {
				this.ec2ConnDetails = "{\"NoConnectorSelected\":{\"awsAccountId\":0,\"id\":0,\"connectorState\":0}}";
			} else {
				this.ec2ConnDetails = ec2ConnDetails;
			}
			JsonObject jo = (JsonObject) jsonParser.parse(this.ec2ConnDetails);
			this.ec2ConnName = jo.keySet().toString().replaceAll("\\[|\\]", "");
			JsonObject i = jo.get(this.ec2ConnName).getAsJsonObject();
			this.ec2ConnAccountId = i.get("awsAccountId").getAsString();
			this.ec2ConnId = i.get("id").getAsString();
		}

		if (createAuthRecord) {
			this.unixAndWindowsCredentials = unixAndWindowsCredentials;
			this.unixAndWindowsCredentialsId = unixAndWindowsCredentialsId;
		}

		this.pollingInterval = pollingInterval;
		this.vulnsTimeout = vulnsTimeout;
		this.selectedPolicies = selectedPolicies;

		if (failByStateAndCriticality) {
			this.stateFail = stateFail;
			this.stateError = stateError;
			this.stateExceptions = stateExceptions;

			this.criticalitySerious = criticalitySerious;
			this.criticalityUrgent = criticalityUrgent;
			this.criticalityCritical = criticalityCritical;
			this.criticalityMedium = criticalityMedium;
			this.criticalityMinimal = criticalityMinimal;

		}

		this.failByAuth = failByAuth;
		if (excludedCriteria) {
			this.excludedCids = excludedCids;
		}

	} // End of Constructor

	@Symbol("qualysPolicyComplianceScanner")
	@Extension
	public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {

		private static final String DISPLAY_NAME = "Scan host/instances with Qualys PC";

		public FormValidation doCheckName(@QueryParameter String value, @QueryParameter boolean useFrench)
				throws IOException, ServletException {

			return FormValidation.ok();
		}

		private static final String URL_REGEX = "^(https)://qualysapi\\.[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
		private static final String PROXY_REGEX = "^((https?)://)?[-a-zA-Z0-9+&@#/%?=~_|!,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
		private static final String TIMEOUT_PERIOD_REGEX = "^(\\d+[*]?)*(?<!\\*)$";
		private static final String HOST_IP = "^\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b";
		private static final String awsAccountId = "awsAccountId";
		private static final String utf8Error = "Provide valid UTF-8 string value.";
		private static final String displayName = "Scan host/instances with Qualys PC";
		static JsonObject ctorNameList = new JsonObject();
		Helper h = new Helper();

		@Override
		public String getDisplayName() {
			return displayName;
		}

		@Override
		public boolean isApplicable(Class<? extends AbstractProject> jobType) {
			return true;
		}

		public FormValidation doCheckApiServer(@QueryParameter String apiServer) {
			if (isNonUTF8String(apiServer)) {
				return FormValidation.error(utf8Error);
			}
			try {
				String server;
				if (apiServer == null || apiServer.trim().equals("")) {
					return FormValidation.error("Server Name cannot be empty");
				} else {
					server = apiServer.trim();
				}
				Pattern patt = Pattern.compile(URL_REGEX);
				Matcher matcher = patt.matcher(server);

				if (!(matcher.matches())) {
					return FormValidation.error("Server name is not valid! Please use the correct format, refer- https://www.qualys.com/platform-identification/" );
				} else {
					return FormValidation.ok();
				}
			} catch (Exception e) {
				return FormValidation.error(e.getMessage());
			}
		} // End of doCheckApiServer FormValidation

		public FormValidation doCheckCredsId(@QueryParameter String credsId) {
			try {
				if (credsId.trim().equals("")) {
					return FormValidation.error("API Credentials cannot be empty.");
				} else {
					return FormValidation.ok();
				}
			} catch (Exception e) {
				return FormValidation.error(e.getMessage());
			}
		}// End of doCheckCredsId FormValidation

		@POST
		public ListBoxModel doFillCredsIdItems(@AncestorInPath Item item, @QueryParameter String credsId) {
			StandardListBoxModel result = new StandardListBoxModel();
			if (item == null) {
				if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
					return result.add(credsId);
				}
			} else {
				if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
					return result.add(credsId);
				}
			}
			return result.withEmptySelection()
					.withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item,
							null, Collections.<DomainRequirement>emptyList()))
					.withMatching(CredentialsMatchers.withId(credsId));

		} // End of doFillCredsIdItems FormValidation

		@POST
		public ListBoxModel doFillUnixAndWindowsCredentialsIdItems(@AncestorInPath Item item,
				@QueryParameter String unixAndWindowsCredentialsId) {
			StandardListBoxModel result = new StandardListBoxModel();
			if (item == null) {
				if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
					return result.add(unixAndWindowsCredentialsId);
				}
			} else {
				if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
					return result.add(unixAndWindowsCredentialsId);
				}
			}
			return result.withEmptySelection()
					.withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item,
							null, Collections.<DomainRequirement>emptyList()))
					.withMatching(CredentialsMatchers.withId(unixAndWindowsCredentialsId));

		} // End of doFillUnixAndWindowsCredentialsIdItems FormValidation

		public FormValidation doCheckProxyServer(@QueryParameter String proxyServer) {
			if (isNonUTF8String(proxyServer)) {
				return FormValidation.error(utf8Error);
			}
			try {
				String server;
				if (proxyServer == null || proxyServer.trim().equals("")) {
					return FormValidation.error("Proxy server URL cannot be empty");
				} else {
					server = proxyServer.trim();
				}
				Pattern patt = Pattern.compile(PROXY_REGEX);
				Matcher matcher = patt.matcher(server);

				if (!(matcher.matches())) {
					return FormValidation.error("Enter valid server url!");
				} else {
					return FormValidation.ok();
				}
			} catch (Exception e) {
				return FormValidation.error(e.getMessage());
			}

		} // End of doCheckProxyServer FormValidation

		public FormValidation doCheckProxyPort(@QueryParameter String proxyPort) {
			try {
				if (proxyPort != null && !proxyPort.trim().isEmpty()) {
					int proxyPortInt = Integer.parseInt(proxyPort);
					if (proxyPortInt < 1 || proxyPortInt > 65535) {
						return FormValidation.error("Enter a valid port number!");
					}
				} else {
					return FormValidation.error("Port number cannot be empty");
				}
			} catch (Exception e) {
				return FormValidation.error("Enter valid port number!");
			}
			return FormValidation.ok();

		} // End of doCheckProxyPort FormValidation

		@POST
		public ListBoxModel doFillProxyCredentialsIdItems(@AncestorInPath Item item,
				@QueryParameter String proxyCredentialsId) {
			StandardListBoxModel result = new StandardListBoxModel();
			if (item == null) {
				if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
					return result.add(proxyCredentialsId);
				}
			} else {
				if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
					return result.add(proxyCredentialsId);
				}
			}
			return result.withEmptySelection()
					.withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item,
							null, Collections.<DomainRequirement>emptyList()))
					.withMatching(CredentialsMatchers.withId(proxyCredentialsId));

		} // End of doFillProxyCredentialsIdItems FormValidation

		public FormValidation doCheckHostIp(@QueryParameter String hostIp) {
			try {
				if (hostIp != null && StringUtils.isNotBlank(hostIp)) {
					if (hostIp.startsWith("env.")) {
						return FormValidation.ok();
					}
					Pattern patt = Pattern.compile(HOST_IP);
					Matcher matcher = patt.matcher(hostIp);
					if (!(matcher.matches())) {
						return FormValidation.error("Host IP is not in valid format!");
					} else {
						return FormValidation.ok();
					}
				} else {
					return FormValidation.error("Provide a valid Host IP.");
				}
			} catch (Exception e) {
				return FormValidation.error("Enter valid Host Ip!");
			}

		} // End of doCheckHostIp FormValidation

		public FormValidation doCheckScanName(@QueryParameter String scanName) {
			if (isNonUTF8String(scanName)) {
				return FormValidation.error(utf8Error);
			}
			try {
				if (scanName.trim().equals("")) {
					return FormValidation.error("Scan Name cannot be empty.");
				} else {
					if (scanName.length() > 256) {
						return FormValidation.error("Scan Name length must be of 256 or less characters.");
					}
					return FormValidation.ok();
				}
			} catch (Exception e) {
				return FormValidation.error(e.getMessage());
			}

		} // End of doCheckScanName FormValidation

		public FormValidation doCheckEc2Id(@QueryParameter String ec2Id) {
			if (isNonUTF8String(ec2Id)) {
				return FormValidation.error("Provide valid EC2 Instance Id.");
			}
			try {
				if (ec2Id.trim().equals("")) {
					return FormValidation.error("EC2 Instance Id cannot be empty.");
				} else {
					return FormValidation.ok();
				}
			} catch (Exception e) {
				return FormValidation.error(e.getMessage());
			}

		} // End of doCheckEc2Id FormValidation

		public FormValidation doCheckOptionProfile(@QueryParameter String optionProfile) {
			try {
				if (optionProfile.trim().equals("")) {
					return FormValidation.error("Select a Option Profile.");
				} else {
					return FormValidation.ok();
				}
			} catch (Exception e) {
				return FormValidation.error(e.getMessage());
			}

		} // End of doCheckOptionProfile FormValidation

		public FormValidation doCheckFailByStateAndCriticality(@QueryParameter boolean failByStateAndCriticality,
				@QueryParameter boolean stateFail, @QueryParameter boolean stateError,
				@QueryParameter boolean stateExceptions, @QueryParameter boolean criticalitySerious,
				@QueryParameter boolean criticalityUrgent, @QueryParameter boolean criticalityCritical,
				@QueryParameter boolean criticalityMedium, @QueryParameter boolean criticalityMinimal) {
			try {
				if (failByStateAndCriticality) {
					if (stateFail == false && stateError == false && stateExceptions == false) {
						return FormValidation.error("Select at least one state");
					}
					if (criticalitySerious == false && criticalityUrgent == false && criticalityCritical == false
							&& criticalityMedium == false && criticalityMinimal == false) {
						return FormValidation.error("Select at least one criticality");
					}
				}
				return FormValidation.ok();
			} catch (Exception e) {
				return FormValidation.error(e.getMessage());
			}

		} // End of doCheckFailByStateAndCriticality FormValidation

		public FormValidation doCheckExcludedCids(@QueryParameter String excludedCids) {
			if (excludedCids == null || excludedCids.isEmpty()) {
				return FormValidation.ok();
			}
			try {
				if (!Helper.isValidCidList(excludedCids)) {
					return FormValidation.error("Enter valid CID range/numbers!");
				}
				return FormValidation.ok();
			} catch (Exception e) {
				return FormValidation.error("Enter valid CID range/numbers! Error:" + e.getMessage());
			}

		} // End of doCheckExcludedCids FormValidation

		public FormValidation doCheckPollingInterval(@QueryParameter String pollingInterval) {
			try {
				String pollingIntervalVal = pollingInterval.trim();
				if (pollingIntervalVal.equals("")) {
					return FormValidation.ok();
				}
				Pattern patt = Pattern.compile(TIMEOUT_PERIOD_REGEX);
				Matcher matcher = patt.matcher(pollingIntervalVal);

				if (!(matcher.matches())) {
					return FormValidation.error("Timeout period is not valid!");
				}
			} catch (Exception e) {
				return FormValidation.error("Timeout period string : " + pollingInterval + ", reason = " + e);
			}
			return FormValidation.ok();

		} // End of doCheckPollingInterval FormValidation

		public FormValidation doCheckVulnsTimeout(@QueryParameter String vulnsTimeout) {
			String vulnsTimeoutVal = vulnsTimeout.trim();
			try {
				if (vulnsTimeoutVal.equals("")) {
					return FormValidation.ok();
				}
				Pattern patt = Pattern.compile(TIMEOUT_PERIOD_REGEX);
				Matcher matcher = patt.matcher(vulnsTimeoutVal);

				if (!(matcher.matches())) {
					return FormValidation.error("Timeout period is not valid!");
				} else {
					return FormValidation.ok();
				}
			} catch (Exception e) {
				return FormValidation.error("Timeout period string : " + vulnsTimeout + ", reason = " + e);
			}

		} // End of doCheckVulnsTimeout FormValidation

		@POST
		public FormValidation doCheckConnection(@QueryParameter String platform, @QueryParameter String apiServer,
				@QueryParameter String credsId, @QueryParameter String proxyServer, @QueryParameter String proxyPort,
				@QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy,
				@AncestorInPath Item item) {
			item.checkPermission(Item.CONFIGURE);
			try {
				if (doCheckApiServer(apiServer) != FormValidation.ok() && platform.equalsIgnoreCase("pcp")) {
					return FormValidation.error("Connection test failed.");
				}
				else  {
					int proxyPortInt = (doCheckProxyPort(proxyPort) == FormValidation.ok()) ? Integer.parseInt(proxyPort)
							: 80;
					String server = apiServer != null ? apiServer.trim() : "";
					if (!platform.equalsIgnoreCase("pcp")) {
						Map<String, String> platformObj = Helper.platformsList.get(platform);
						server = platformObj.get("url");
					}
					logger.info("Using qualys API Server URL: " + server);
					QualysPCClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt,
							proxyCredentialsId, item);

					if (platform.equalsIgnoreCase("pcp")) {
						client.testConnection();
					} else {
						client.testConnectionUsingGatewayAPI();
					}

					return FormValidation.ok("Connection test successful!");
				}

			} catch (Exception e) {
				return FormValidation.error("Connection test failed. (Reason: " + e.getMessage() + ")");
			}

		} // End of doCheckConnection FormValidation

		@POST
		public ListBoxModel doFillUnixAndWindowsCredentialsItems() {
			StandardListBoxModel model = new StandardListBoxModel();
			Option e1 = new Option("Windows", "windows");
			model.add(e1);
			e1 = new Option("Unix", "unix");
			model.add(e1);
			return model;
		}// End of doFillUnixAndWindowsCredentialsItems ListBoxModel

		@POST
		public ListBoxModel doFillScannerNameItems(@AncestorInPath Item item, @QueryParameter String platform,
				@QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer,
				@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId,
				@QueryParameter boolean useProxy, @QueryParameter boolean useEc2, @QueryParameter boolean useHost) {

			item.checkPermission(Item.CONFIGURE);
			StandardListBoxModel model = new StandardListBoxModel();
			JsonObject scannerList = new JsonObject();
			Option e1 = new Option("Select the scanner appliance (Default - External)", "External");
			model.add(e1);
			try {
				if (filledInputs(platform, apiServer, credsId, useProxy, proxyServer, proxyPort)) {
					int proxyPortInt = (doCheckProxyPort(proxyPort) == FormValidation.ok())
							? Integer.parseInt(proxyPort)
							: 80;
					String server = apiServer != null ? apiServer.trim() : "";
					if (!platform.equalsIgnoreCase("pcp")) {
						Map<String, String> platformObj = Helper.platformsList.get(platform);
						server = platformObj.get("url");
						logger.info("Using qualys API Server URL: " + server);
					}
					QualysPCClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt,
							proxyCredentialsId, item);
					if (useEc2) {
						scannerList = client.scannerName(false);
					} else {
						scannerList = client.scannerName(true);
					}
					for (String name : scannerList.keySet()) {
						JsonObject jk = scannerList.get(name).getAsJsonObject();
						String scanStatus = jk.get("status").getAsString();
						String scanAccId = jk.get("accountId").getAsString();
						if (useEc2) {
							Option e = new Option(
									name + " (Account Id: " + scanAccId + " | Status: " + scanStatus + ")", name);
							model.add(e);
						} else {
							Option e = new Option(name + " (Status: " + scanStatus + ")", name);
							model.add(e);
						}
					}
				} // End of if
			} catch (Exception e) {
				logger.warning("Error to get scanner list. " + e.getMessage());
				Option ee = new Option(e.getMessage(), "");
				model.add(ee);
				return model;
			}
			model.sort(Helper.getOptionItemmsComparator());
			return model;
		}// End of doFillScannerNameItems ListBoxModel

		public ListBoxModel doFillPlatformItems() {
			ListBoxModel model = new ListBoxModel();
			for (Map<String, String> platform : getPlatforms()) {
				Option e = new Option(platform.get("name"), platform.get("code"));
				model.add(e);
			}
			return model;
		}

		@POST
		public ListBoxModel doFillOptionProfileItems(@AncestorInPath Item item, @QueryParameter String platform,
				@QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer,
				@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId,
				@QueryParameter boolean useProxy) {
			item.checkPermission(Item.CONFIGURE);
			StandardListBoxModel model = new StandardListBoxModel();
			Set<String> nameList = new HashSet<String>();
			Option e1 = new Option("Select the Option Profile", "");
			model.add(e1);
			try {
				if (filledInputs(platform, apiServer, credsId, useProxy, proxyServer, proxyPort)) {
					int proxyPortInt = (doCheckProxyPort(proxyPort) == FormValidation.ok())
							? Integer.parseInt(proxyPort)
							: 80;
					String server = apiServer != null ? apiServer.trim() : "";
					if (!platform.equalsIgnoreCase("pcp")) {
						Map<String, String> platformObj = Helper.platformsList.get(platform);
						server = platformObj.get("url");
						logger.info("Using qualys API Server URL: " + server);
					}
					QualysPCClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt,
							proxyCredentialsId, item);
					logger.info("Fetching Option Profiles list ... ");
					optionProfileRawData = client.optionProfiles();
					nameList = client.optionProfilesSet(optionProfileRawData.getResponseXml(),
							optionProfileRawData.getResponseCode(), "Option Profile PC");
					for (String name : nameList) {
						JSONObject jsonOptionDetails = new JSONObject();
						String[] nameAndID = name.split(":");
						JSONObject jsonPolicyDetails = allPolicies(nameAndID[0]);
						jsonOptionDetails.put("optionProfileName", nameAndID[0]);
						jsonOptionDetails.put("optionProfileID", nameAndID[1]);
						jsonOptionDetails.put("policyDetails", jsonPolicyDetails);
						Option e = new Option(nameAndID[0], String.valueOf(jsonOptionDetails));
						model.add(e);
					}
				} // End of if
			} catch (Exception e) {
				logger.warning("Error to get option profile list. " + e.getMessage());
				Option ee = new Option(e.getMessage(), "");
				model.add(ee);
				return model;
			}
			model.sort(Helper.getOptionItemmsComparator());
			return model;
		} // End of doFillOptionProfileItems ListBoxModel

		public JSONObject allPolicies(String optionProfile) {
			JSONObject jsonPolicyDetails = new JSONObject();

			if (optionProfileRawData != null) {
				Document resp = optionProfileRawData.getResponseXml();
				NodeList opList = resp.getElementsByTagName("OPTION_PROFILE");
				try {
					for (int i = 0; i < opList.getLength(); i++) {
						Node nNode = opList.item(i);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eElement = (Element) nNode;

							NodeList pList = eElement.getElementsByTagName("POLICY");
							if (optionProfile.toLowerCase().equals(eElement.getElementsByTagName("GROUP_NAME").item(0)
									.getTextContent().toLowerCase())) {
								for (int j = 0; j < pList.getLength(); j++) {
									Node pNode = pList.item(j);
									Element pElement = (Element) pNode;
									jsonPolicyDetails.put(
											pElement.getElementsByTagName("TITLE").item(0).getTextContent(),
											pElement.getElementsByTagName("ID").item(0).getTextContent());
								}
								break;
							}
						} // End of if
					} // End of outer for loop

				} catch (Exception e) {
					logger.warning("Error to get policy list. " + e.getMessage());
				}
			}
			return jsonPolicyDetails;
		}

		@POST
		public ListBoxModel doFillEc2ConnDetailsItems(@AncestorInPath Item item, @QueryParameter String platform,
				@QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer,
				@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId,
				@QueryParameter boolean useProxy, @QueryParameter boolean useEc2) {
			item.checkPermission(Item.CONFIGURE);
			StandardListBoxModel model = new StandardListBoxModel();
			Option e1 = new Option("--select--", "");
			model.add(e1);
			try {
				if (useEc2 && filledInputs(platform, apiServer, credsId, useProxy, proxyServer, proxyPort)) {
					int proxyPortInt = (doCheckProxyPort(proxyPort) == FormValidation.ok())
							? Integer.parseInt(proxyPort)
							: 80;
					String server = apiServer != null ? apiServer.trim() : "";
					if (!platform.equalsIgnoreCase("pcp")) {
						Map<String, String> platformObj = Helper.platformsList.get(platform);
						server = platformObj.get("url");
						logger.info("Using qualys API Server URL: " + server);
					}
					QualysPCClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt,
							proxyCredentialsId, item);
					logger.info("Fetching Ec2 connector name list ... ");
					ctorNameList = client.getConnector();
					for (String name : ctorNameList.keySet()) {
						JsonObject jk = ctorNameList.get(name).getAsJsonObject();
						JsonObject ConName = new JsonObject();
						JsonObject ConNameDetails = new JsonObject();
						String accId = jk.get(awsAccountId).getAsString();
						String connectorState = jk.get("connectorState").getAsString();
						ConNameDetails.addProperty(awsAccountId, accId);
						ConNameDetails.addProperty("id", jk.get("id").getAsString());
						ConName.add(name, ConNameDetails);
						Option e = new Option(name + " (Account Id:" + accId + " | State:" + connectorState + ")",
								ConName.toString());
						model.add(e);
					}
				} // End of if
			} catch (Exception e) {
				Option e2 = new Option(e.getMessage(), "");
				model.add(e2);
				logger.warning("There is an error while fetching the connectors list. " + e);
				return model;
			}
			model.sort(Helper.getOptionItemmsComparator());
			return model;
		} // End of doFillEc2ConnNameItems ListBoxModel

		public boolean isNonUTF8String(String string) {
			if (string != null && !string.isEmpty()) {
				try {
					byte[] bytes = string.getBytes(java.nio.charset.StandardCharsets.UTF_8);
				} catch (Exception e) {
					return true;
				}
			}
			return false;
		}

		public boolean filledInputs(String platform, String apiServer, String credsId, boolean useProxy,
				String proxyServer, String proxyPort) {
			if (platform.equalsIgnoreCase("pcp") && StringUtils.isBlank(apiServer))
				return false;
			if (StringUtils.isBlank(credsId))
				return false;
			if (useProxy && StringUtils.isBlank(proxyServer))
				return false;
			return true;
		}// End of filledInputs method

		public List<Map<String, String>> getPlatforms() {
			List<Map<String, String>> result = new ArrayList<Map<String, String>>();
			for (Map.Entry<String, Map<String, String>> platform : Helper.platformsList.entrySet()) {
				Map<String, String> obj = platform.getValue();
				result.add(obj);
			}
			return result;
		}

	}/* End of DescriptorImpl class */

	/*
	 * From this point the Scan Run process is starts. The PCScanLauncher class will
	 * be used here.
	 */
	/* ###################################### */

	@Override
	public BuildStepMonitor getRequiredMonitorService() {
		return BuildStepMonitor.NONE;
	}

	public String getPluginVersion() {
		try {
			MavenXpp3Reader reader = new MavenXpp3Reader();
			Model model;
			if ((new File("pom.xml")).exists())
				model = reader.read(new FileReader("pom.xml"));
			else
				model = reader.read(new InputStreamReader(PCScanNotifier.class
						.getResourceAsStream("/META-INF/maven/com.qualys.plugins/qualys-pc/pom.xml")));
			return model.getVersion();
		} catch (Exception e) {
			logger.info("Exception while reading plugin version; Reason :" + e.getMessage());
			return "unknown";
		}
	}// end of getPluginVersion method

	@SuppressWarnings("null")
	@Override
	public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath filePath, @Nonnull Launcher launcher,
			@Nonnull TaskListener taskListener) throws InterruptedException, IOException {
		long startTime = System.currentTimeMillis();
		Item project = null;
		logger.info("Triggered build #" + run.number);
		try {
			String version = getPluginVersion();
			taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " " + pluginName
					+ " scan task started (version-" + version + ").");
			logger.info(pluginName + " (version-" + version + ") started.");
		} catch (Exception e) {
			taskListener.getLogger()
					.println(new Timestamp(System.currentTimeMillis()) + " " + pluginName + " scan task - Started.");
			logger.info(pluginName + " started.");
		}

		// This method will extract ec2Id and hostIp from environment variables
		extractEnvVariables(run.getEnvironment(taskListener), taskListener);

		if ((useHost && StringUtils.isNotBlank(hostIp)) || (useEc2 && StringUtils.isNotBlank(ec2Id))) {
			try {
				project = run.getParent();
				launchHostScan(run, taskListener, project);
			} catch (Exception e) {
				if (e.toString().equalsIgnoreCase("java.lang.Exception")) {
					throw new AbortException("Exception in " + pluginName + " scan result. Finishing the build.");
				} else if (e.getMessage().equalsIgnoreCase("sleep interrupted")) {
					logger.log(Level.SEVERE, "Error: User Aborted");
					throw new AbortException("Exception in " + pluginName + " scan result: User Aborted");
				} else {
					logger.log(Level.SEVERE, "Error: " + e.getMessage());
					throw new AbortException("Exception in " + pluginName
							+ " scan result: Finishing the build. Reason: " + e.getMessage());
				}
			} finally {
				long endTime = System.currentTimeMillis();
				long time = endTime - startTime;
				taskListener.getLogger().println(new Timestamp(System.currentTimeMillis())
						+ " Total time taken to complete the build: " + Helper.longToTime(time));
				logger.info("Total time taken to complete the build: " + Helper.longToTime(time));
			}
		} else {
			taskListener.getLogger()
					.println(new Timestamp(System.currentTimeMillis()) + " No Host IP or EC2 Instance Id Configured.");
			throw new AbortException("Host IP or EC2 Instance Id can't be set to null or empty.");
		}
		return;
	}// End of perform method

	public void launchHostScan(Run<?, ?> run, TaskListener listener, Item project) throws Exception {
		// Set username and password for the portal
		JsonObject connectorState = new JsonObject();
		connectorState.addProperty("state", true);
		JsonObject instanceState = new JsonObject();
		instanceState.addProperty("endpoint", "Unknown");
		Helper h = new Helper();
		QualysAuth auth = new QualysAuth();
		String instanceStatus = new String();

		Map<String, String> platformObj = Helper.platformsList.get(platform);
		String portalUrl = apiServer;
		// set apiServer URL according to platform
		if (!platform.equalsIgnoreCase("pcp")) {
			setApiServer(platformObj.get("url"));
			logger.info("Using qualys API Server URL: " + apiServer);
		}
		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Qualys Platform: " + platform
				+ ". Using Qualys API server: " + apiServer);

		QualysPCClient client = h.getClient(useProxy, apiServer, credsId, proxyServer, proxyPort, proxyCredentialsId,
				project);
		try {
			String log = " Testing connection with Qualys API Server...";
			String log1 = " Test connection successful.";
			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + log);
			logger.info(log);
			if (platform.equalsIgnoreCase("pcp")) {
				client.testConnection();
			} else {
				client.testConnectionUsingGatewayAPI();
			}

			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + log1);
			logger.info(log1);
		} catch (Exception e) {
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			listener.getLogger().println(
					new Timestamp(System.currentTimeMillis()) + " Test connection failed. Reason: " + e.getMessage());
			throw new Exception(e.getMessage());
		} // end of test connection

		try {
			auth = h.getQualysAuth(useProxy, apiServer, credsId, proxyServer, proxyPort, proxyCredentialsId, project);
		} catch (Exception e) {
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			listener.getLogger().println(new Timestamp(System.currentTimeMillis())
					+ " Error while setting Qualys Credentials. Reason: " + e.getMessage());
			throw new Exception(e.getMessage());
		} // end of setting Qualys Credentials

		try {
			if (useEc2) {
				PCScanEc2ConnectorLauncher ctor = new PCScanEc2ConnectorLauncher(run, listener, pollingInterval,
						vulnsTimeout, auth, useEc2, this.ec2ConnId, this.ec2ConnName);
				// Get instance state and endpoint
				listener.getLogger()
						.println(new Timestamp(System.currentTimeMillis()) + " Checking the state of instance("
								+ this.ec2IdValue + ") with instance account(" + this.ec2ConnAccountId + ")");
				// Get state of Instance
				instanceState = ctor.checkInstanceState(this.ec2IdValue, this.ec2ConnAccountId);
				instanceStatus = instanceState.get("instanceState").getAsString();

				if (instanceState.get("count").getAsInt() == 0) {
					// Get state of connector
					listener.getLogger().println(new Timestamp(System.currentTimeMillis())
							+ " Checking the state of connector: " + this.ec2ConnName);
					String ec2ConnState = ctor.getCtorStatus(this.ec2ConnId, true);

					// log message for checkbox status
					String logMsg = " Run connector checkbox: " + (runConnector ? "checked" : "unchecked");
					logger.info(logMsg);
					listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + logMsg);
					boolean recheckInstanceState = false;
					// If checkbox is checked, decide weather to run the connector depending upon
					// the connector state and instance state
					if (!runConnector && !instanceStatus.equalsIgnoreCase("RUNNING")) {
						// If check box is not check and instance is not running, abort the build
						throw new Exception("Instance state is: " + instanceStatus
								+ ". Could not find the provided instance ID with a given EC2 configuration. "
								+ "The user might have provided the wrong instance/connector/scanner details. "
								+ "Re-check the EC2 details provided for the scan.");
					} else if (runConnector && runCtorDecision(ec2ConnState, listener)) {
						// if the connector is not in ENDING/PROCESSING/QUEUED/RUNNING, run connector
						logger.info(pluginName + " task - Started running the Ec2 Connector: " + ec2ConnName);
						ctor.runCtor();
						logger.info(pluginName + " task - Finished running Ec2 Connector: " + ec2ConnName);
						recheckInstanceState = true;
					} else if (runConnector && !runCtorDecision(ec2ConnState, listener)) {
						// if the connector is in PENDING/PROCESSING/QUEUED/RUNNING, do polling
						ctor.ctorPolling(ec2ConnId, false);
						recheckInstanceState = true;
					}

					if (recheckInstanceState) {
						// Get instance state and endpoint
						listener.getLogger()
								.println(new Timestamp(System.currentTimeMillis()) + " Checking the state of instance("
										+ this.ec2IdValue + ") with instance account(" + this.ec2ConnAccountId + ")");
						// Get state of Instance
						instanceState = ctor.checkInstanceState(this.ec2IdValue, this.ec2ConnAccountId);
						instanceStatus = instanceState.get("instanceState").getAsString();

						if (!instanceStatus.equalsIgnoreCase("RUNNING")) {
							// If instance is not running, abort the build
							throw new Exception("Instance state is: " + instanceStatus
									+ ". Could not find the provided instance ID with a given EC2 configuration. "
									+ "The user might have provided the wrong instance/connector/scanner details. "
									+ "Re-check the EC2 details provided for the scan.");
						}
					}

				}
			} // end of checking if EC2 is selected
		} catch (Exception e) {
			listener.getLogger().println(new Timestamp(System.currentTimeMillis())
					+ " Error while checking ec2 details. Reason: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			throw new Exception(e.getMessage());
		} // end of checking ec2 details

		try {
			String ec2PrivateIpAddress = "";
			if (useEc2) {
				ec2PrivateIpAddress = instanceState.get("ec2PrivateIpAddress").getAsString();
			}
			if (selectedPolicies != null && !selectedPolicies.isEmpty()) {
				JSONObject jsonPolicyDetails = new JSONObject();
				String[] allPolicy = selectedPolicies.split(",,");
				for (int i = 0; i < allPolicy.length; i++) {
					String[] policyDetails = allPolicy[i].split("::");
					jsonPolicyDetails.put(policyDetails[0], policyDetails[1]);
				}
				this.selectedPoliciesJson = jsonPolicyDetails;
			} else {
				throw new Exception(
						"No policies are selected for the scan or there are no policies present in the selected option profile.");
			}

			JsonParser jsonParser = new JsonParser();
			if (!this.optionProfile.trim().equals("")) {
				JsonObject optionProfileJson = (JsonObject) jsonParser.parse(this.optionProfile);
				this.optionProfileName = optionProfileJson.get("optionProfileName").getAsString();
			}

			PCScanLauncher launcher = new PCScanLauncher(run, listener, hostIpValue, ec2IdValue, ec2ConnName,
					instanceState.get("endpoint").getAsString(), ec2PrivateIpAddress, scannerName, scanName,
					optionProfileName, pollingInterval, vulnsTimeout, useHost, useEc2, auth, selectedPoliciesJson,
					this.stateFail, this.stateError, this.stateExceptions, this.criticalitySerious,
					this.criticalityUrgent, this.criticalityCritical, this.criticalityMedium, this.criticalityMinimal,
					this.failByAuth, this.excludedCids, this.unixAndWindowsCredentialsId,
					this.unixAndWindowsCredentials, this.failByStateAndCriticality, this.excludedCriteria);
			launcher.addHost();

			if (this.createAuthRecord) {
				launcher.addAuthRecord();
			}

			launcher.addAssetGroup();

			launcher.updatePoliciesWithAssetGroup();
			boolean scanResult = launcher.getLaunchScanResult();

			// if (scanResult && this.failByStateAndCriticality) {
			if (scanResult) {
				launcher.getAndProcessLaunchReport();
			}
			listener.getLogger()
					.println(new Timestamp(System.currentTimeMillis()) + " " + pluginName + " scan task - Finished.");
			logger.info(pluginName + " task - Finished.");
		} catch (Exception e) {
			listener.getLogger()
					.println(new Timestamp(System.currentTimeMillis()) + " Build stopped. Reason: " + e.getMessage());
			throw new Exception(e.getMessage());
		} // end of launching the scan
	} // End of launchHostScan method

	public boolean runCtorDecision(String ec2ConnState, TaskListener listener) throws Exception {
		boolean run = false;
		List<String> conRunList = new ArrayList<String>();
		List<String> conNoRunList = new ArrayList<String>();
		conRunList.add("FINISHED_ERRORS");
		conRunList.add("ERROR");
		conRunList.add("INCOMPLETE");
		conRunList.add("FINISHED_SUCCESS");
		conRunList.add("SUCCESS");
		conNoRunList.add("RUNNING");
		conNoRunList.add("PENDING");
		conNoRunList.add("QUEUED");
		conNoRunList.add("PROCESSING");

		if (ec2ConnState.equalsIgnoreCase("DISABLED")) {
			logger.warning("Connector is in " + ec2ConnState + " state. Aborting!!");
			throw new Exception("Connector is in " + ec2ConnState + " state. Aborting!!");
		} else if (conNoRunList.contains(ec2ConnState)) {
			logger.warning("Connector state is " + ec2ConnState + ". Not running the connector!");
			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Connector state is "
					+ ec2ConnState + ". Not running the connector!");
			run = false;
		} else if (conRunList.contains(ec2ConnState)) {
			logger.warning("Connector state is " + ec2ConnState + ". Running the connector!");
			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Connector state is "
					+ ec2ConnState + ". Running the connector!");
			run = true;
		}
		return run;
	}

	private void extractEnvVariables(EnvVars envVars, TaskListener listener) throws AbortException {
		if (useHost && hostIp != null && !hostIp.isEmpty()) {
			if (hostIp.startsWith("env.") && envVars != null && !envVars.isEmpty()) {
				String envHostIpKey = hostIp.replaceFirst("env.", "");
				hostIpValue = envVars.get(envHostIpKey);
				if (hostIpValue != null && !hostIpValue.isEmpty()) {
					logger.info("Host IP value from environment variable is - " + hostIpValue);
					listener.getLogger().println(new Timestamp(System.currentTimeMillis())
							+ " Host IP value from environment variable is - " + hostIpValue);
				} else {
					throw new AbortException("Host IP - Environment variable " + envHostIpKey + " is missing !!");
				}
			} else {
				hostIpValue = hostIp;
			}

		}
		if (useEc2 && ec2Id != null && !ec2Id.isEmpty()) {
			if (ec2Id.startsWith("env.") && envVars != null && !envVars.isEmpty()) {
				String envEc2IdKey = ec2Id.replaceFirst("env.", "");
				ec2IdValue = envVars.get(envEc2IdKey);
				if (ec2IdValue != null && !ec2IdValue.isEmpty()) {
					logger.info("ec2Id value from environment variable is - " + ec2IdValue);
					listener.getLogger().println(new Timestamp(System.currentTimeMillis())
							+ " ec2Id value from environment variable is - " + ec2IdValue);
				} else {
					throw new AbortException("Host IP - Environment variable " + envEc2IdKey + " is missing !!");
				}
			} else {
				ec2IdValue = ec2Id;
			}

		}
	}

} // End of PCScanNotifier class
