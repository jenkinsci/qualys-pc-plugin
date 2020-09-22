package com.qualys.plugins.pc.client;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.qualys.plugins.pc.auth.QualysAuth;

import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
import hudson.AbortException;
import hudson.model.TaskListener;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.SocketException;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

public class QualysPCClient extends QualysBaseClient {
	HashMap<String, String> apiMap;
	Logger logger = Logger.getLogger(QualysPCClient.class.getName());
	private static String conRefuse = " Error: Connection refused, contact service provider.";
	private static String exceptionWhileTorun = "Exception to run";
	private static String exceptionWhileToget = "Exception to get";
	private static String responseCode = " Response Code: ";
	private static String nullMessage = " Error: No data. Check credentials or toggle between Host IP/Ec2 Target's radio button. Contact support for more details.";
	private int pollingIntervalForVulns;
	private int vulnsTimeout;
	private TaskListener listener;
	private String token = null;
	private int retryInterval = 5;
	private int retryCount = 5;
	private String tmp_token = "";
	private static String empty = "";

	public QualysPCClient(QualysAuth auth) {
		super(auth, System.out);
		this.populateApiMap();
	}

	public QualysPCClient(QualysAuth auth, PrintStream stream) {
		super(auth, stream);
		this.populateApiMap();
	}

	public QualysPCClient(QualysAuth auth, PrintStream stream, int pollingInterval, int vulTimeout,
			TaskListener listener) {
		super(auth, stream);
		this.populateApiMap();
		this.pollingIntervalForVulns = pollingInterval;
		this.vulnsTimeout = vulTimeout;
		this.listener = listener;
	}

	private void populateApiMap() {
		this.apiMap = new HashMap<>();
		// Ref - https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf
		this.apiMap.put("aboutDotPhp", "/msp/about.php");
		this.apiMap.put("getAuth", "/auth");// [POST]
		this.apiMap.put("scannerName", "/api/2.0/fo/appliance/?action=list&output_mode=full"); // [GET]
		this.apiMap.put("ec2ScannerName",
				"/api/2.0/fo/appliance/?action=list&platform_provider=ec2&include_cloud_info=1&output_mode=full"); // [GET]
		this.apiMap.put("optionProfilesPc", "/api/2.0/fo/subscription/option_profile/pc/?action=list"); // [GET]
		this.apiMap.put("launchPCScan", "/api/2.0/fo/scan/compliance/?action=launch"); // [POST]
		this.apiMap.put("cancelPcScan", "/api/2.0/fo/scan/compliance/?action=cancel"); // [POST]
		this.apiMap.put("getReportResult", "/api/2.0/fo/compliance/posture/info/?action=list"); // [POST]
		this.apiMap.put("pCScansList", "/api/2.0/fo/scan/compliance/?action=list"); /// [GET][POST]
		this.apiMap.put("getConnector", "/qps/rest/2.0/search/am/awsassetdataconnector/"); // [GET]
		this.apiMap.put("runConnector", "/qps/rest/2.0/run/am/assetdataconnector"); // [POST]
		this.apiMap.put("getConnectorStatus", "/qps/rest/2.0/get/am/assetdataconnector"); // [GET]
		this.apiMap.put("getScanResult", "/api/2.0/fo/scan/compliance/?action=fetch"); // [GET]
		this.apiMap.put("addHost", "/api/2.0/fo/asset/ip/?action=add&enable_pc=1"); // [POST]
		this.apiMap.put("addWindowsRecord", "/api/2.0/fo/auth/windows/?action=create"); // [POST]
		this.apiMap.put("addUnixRecord", "/api/2.0/fo/auth/unix/?action=create"); // [POST]

		this.apiMap.put("updateWindowsRecord", "/api/2.0/fo/auth/windows/?action=update"); // [POST]
		this.apiMap.put("updateUnixRecord", "/api/2.0/fo/auth/unix/?action=update"); // [POST]

		this.apiMap.put("listUnixAuthRecord", "/api/2.0/fo/auth/unix/?action=list"); // [POST]
		this.apiMap.put("listWindowsAuthRecord", "/api/2.0/fo/auth/windows/?action=list"); // [POST]

		this.apiMap.put("createAssetGroup", "/api/2.0/fo/asset/group/?action=add"); // [POST]

		this.apiMap.put("listAssetGroup", "/api/2.0/fo/asset/group/?action=list"); // [POST]
		this.apiMap.put("updateAssetGroup", "/api/2.0/fo/asset/group/?action=edit"); // [POST]

		this.apiMap.put("updatePolicies", "/api/2.0/fo/compliance/policy/?action=add_asset_group_ids"); // [POST]

		this.apiMap.put("getInstanceState",
				"/qps/rest/2.0/search/am/hostasset?fields=sourceInfo.list.Ec2AssetSourceSimple.instanceState,sourceInfo.list.Ec2AssetSourceSimple.region,sourceInfo.list.Ec2AssetSourceSimple.privateIpAddress"); // [POST]
	} // End of populateApiMap method

	/* API calling methods */

	public JsonObject scannerName(boolean useHost) throws Exception {
		logger.info("Scanner Name is accepted and getting the DOC.");
		NodeList dataList = null;
		Document response = null;
		JsonObject scannerList = new JsonObject();
		QualysPCResponse resp = new QualysPCResponse();
		int retry = 0;
		try {
			while (retry < 3) {
				logger.info("Retrying Scanner Name API call: " + retry);
				if (useHost) {
					resp = this.get(this.apiMap.get("scannerName"), false);
				} else {
					resp = this.get(this.apiMap.get("ec2ScannerName"), false);
				}
				logger.info("Response code received for Scanner Name API call:" + resp.getResponseCode());
				response = resp.getResponseXml();
				if (resp.getResponseCode() == 401) {
					throw new Exception("401 Unauthorised: Access to this resource is denied.");
				} else if (resp.getResponseCode() != 200) {
					throw new Exception(exceptionWhileToget + " the Scanner list." + responseCode
							+ resp.getResponseCode() + conRefuse);
				}
				if (resp != null && resp.getResponseCode() == 200) {
					if (useHost) {
						scannerList = getScannerDetails(response, false);
					} else {
						scannerList = getScannerDetails(response, true);
					}
					break;
				} else {
					retry++;
					dataList = response.getElementsByTagName("RESPONSE");
					for (int temp = 0; temp < dataList.getLength(); temp++) {
						Node nNode = dataList.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eElement = (Element) nNode;
							throw new Exception(
									"API Error code: " + eElement.getElementsByTagName("CODE").item(0).getTextContent()
											+ " | API Error message: "
											+ eElement.getElementsByTagName("TEXT").item(0).getTextContent());
						}
					}
				}

			}
		} catch (Exception e) {
			if (e.getMessage() == null) {
				throw new Exception(exceptionWhileToget + " the Scanner list." + responseCode + resp.getResponseCode()
						+ nullMessage);
			} else {
				throw new Exception(exceptionWhileToget + " the Scanner list." + responseCode + resp.getResponseCode()
						+ " Details: " + e.getMessage());
			}
		}
		return scannerList;
	}// End of scannerName

	public QualysPCResponse optionProfiles() throws Exception {
		logger.info("Option Profile is accepted and getting the DOC.");
		int retryPC = 0;
		try {
			return getList(retryPC, "Option Profile PC", "optionProfilesPc");
		} catch (Exception e) {
			throw new Exception(e.getMessage());
		}
	}// End of optionProfiles

	public QualysPCResponse updatePolicies(String apiParams) throws Exception {
		return this.post(this.apiMap.get("updatePolicies") + apiParams, "", "");
	} // End of updatePolicies

	public QualysPCResponse updateAssetGroup(String assetGroupId, String ipAddress) throws Exception {
		String apiParams = "&id=" + assetGroupId + "&set_ips=" + ipAddress;
		return this.post(this.apiMap.get("updateAssetGroup") + apiParams, "", "");
	} // End of updateAssetGroup

	public QualysPCResponse listAssetGroup(String apiParams) throws Exception {
		return this.post(this.apiMap.get("listAssetGroup") + apiParams, "", "");
	} // End of listAssetGroup

	public QualysPCResponse createAssetGroup(String job_name, String ipAddress) throws Exception {
		String apiParams = "&title=Jenkins_AG_" + job_name + "&ips=" + ipAddress;
		return this.post(this.apiMap.get("createAssetGroup") + apiParams, "", "");
	} // End of createAssetGroup

	public QualysPCResponse updateWindowsAuthRecord(String apiParams, String recordId) throws Exception {
		apiParams = apiParams + "&ids=" + recordId;
		return this.post(this.apiMap.get("updateWindowsRecord") + apiParams, "", "");
	} // End of updateWindowsAuthRecord

	public QualysPCResponse updateUnixAuthRecord(String apiParams, String recordId) throws Exception {
		apiParams = apiParams + "&ids=" + recordId;
		return this.post(this.apiMap.get("updateUnixRecord") + apiParams, "", "");
	} // End of createUnixAuthRecord

	public QualysPCResponse createUnixAuthRecord(String apiParams, String job_name) throws Exception {
		apiParams = apiParams + "&title=Jenkins_Unix_" + job_name;
		return this.post(this.apiMap.get("addUnixRecord") + apiParams, "", "");
	} // End of createUnixAuthRecord

	public QualysPCResponse createWindowsAuthRecord(String apiParams, String job_name) throws Exception {
		apiParams = apiParams + "&title=Jenkins_Windows_" + job_name;
		return this.post(this.apiMap.get("addWindowsRecord") + apiParams, "", "");
	} // End of createUnixAuthRecord

	public QualysPCResponse listUnixAuthRecord(String title) throws Exception {
		return this.post(this.apiMap.get("listUnixAuthRecord") + "&title=" + title, "", "");
	} // End of listUnixAuthRecord

	public QualysPCResponse listWindowsAuthRecord(String title) throws Exception {
		return this.post(this.apiMap.get("listWindowsAuthRecord") + "&title=" + title, "", "");
	} // End of listWindowsAuthRecord

	public QualysPCResponse addHost(String ip) throws Exception {
		return this.post(this.apiMap.get("addHost") + "&ips=" + ip, "", "");
	} // End of addHost

	public QualysPCResponse launchPcScan(String requestData) throws Exception {
		return this.post(this.apiMap.get("launchPCScan"), requestData, "");
	} // End of launchPcScan

	public QualysPCResponse cancelPcScan(String scanRef) throws Exception {
		return this.post(this.apiMap.get("cancelPcScan") + "&scan_ref=" + scanRef, "", "");
	} // End of cancelVmScan

	public QualysPCResponse pCScansList(String statusId) throws Exception {
		return this.get(this.apiMap.get("pCScansList") + "&scan_ref=" + statusId, false);
	} // End of vMScansList

	public QualysPCResponse getReportResult(String apiParams) throws Exception {
		return this.post(this.apiMap.get("getReportResult") + apiParams, "", "");
	} // End of getReportResult

	public QualysPCResponse getPCScanResult(String scanRef) throws Exception {
		return this.post(this.apiMap.get("getScanResult") + "&scan_ref=" + scanRef, "", "");
	} // End of getPCScanResult

	// for pcp
	public QualysPCResponse aboutDotPhp() throws Exception {
		return this.get(this.apiMap.get("aboutDotPhp"), false);
	} // End of aboutDotPhp

	// for pcp
	public void testConnection() throws Exception {
		QualysPCResponse response = new QualysPCResponse();
		try {
			response = aboutDotPhp();
			if (response.isErrored()) {
				throw new Exception("Please provide valid API and/or Proxy details."
						+ " Server returned with Response code: " + response.getResponseCode());
			} else {
				Document resp = response.getResponseXml();
				if (response.getResponseCode() < 200 || response.getResponseCode() > 299) {
					throw new Exception("HTTP Response code from server: " + response.getResponseCode()
							+ ". API Error Message: " + response.getErrorMessage());
				} else if (response.getResponseCode() != 200) {
					throw new Exception(exceptionWhileTorun + " test connection." + responseCode
							+ response.getResponseCode() + conRefuse);
				}

				logger.info("Root element :" + resp.getDocumentElement().getNodeName());
				String responseCodeString = getTextValueOfXml(resp, "ABOUT", "WEB-VERSION", empty, empty, "connection");
				logger.info("WEB-VERSION: " + responseCodeString);

				int majorVersion = -1;
				if (responseCodeString != null) {
					try {
						String[] version = responseCodeString.split("\\.");
						majorVersion = Integer.parseInt(version[0]);
					} catch (Exception e) {
						logger.info("Exception while fetching major version from QWEB version " + e);
					}

				}

				if (majorVersion != -1 && majorVersion < 8) {
					throw new Exception("The QWEB version is less than 8. Are you using older QWEB version? Version: "
							+ responseCodeString);
				}

			} // end of else
		} catch (Exception e) {
			if (e.getMessage() == null) {
				throw new Exception(exceptionWhileTorun + " test connection." + responseCode
						+ response.getResponseCode() + nullMessage);
			} else if (e.getMessage().contains("ACCESS DENIED")) {
				throw new Exception("response code : 401; Please provide valid Qualys credentials");
			}
			else {
				throw new Exception(e.getMessage());
			}
		} // End of catchs
	} // End of testConnection method

	// Test connection method rewritten for testing connection using gateway api
	public void testConnectionUsingGatewayAPI() throws Exception {
		String errorMessage = "";
		CloseableHttpResponse response = null;
		try {
			response = getAuthToken();
			boolean isValidToken = false;
			if (response.getStatusLine().getStatusCode() == 201) {
				logger.info("Token Generation Successful");
				isValidToken = validateSubscription(this.tmp_token);
				logger.info("Is Valid Token : " + isValidToken);

				if (isValidToken) {
					this.token = this.tmp_token;
					this.tmp_token = "";
				} else {
					errorMessage = "Token validation Failed. PC module is not activated for provided user.";
					logger.info("Token validation Failed");
					throw new Exception(errorMessage);
				}
			} else if (response.getStatusLine().getStatusCode() == 401) {
				logger.info("Connection test failed; " + this.tmp_token);
				errorMessage = "Connection test failed; response code : 401; Please provide valid Qualys credentials";
				throw new Exception(errorMessage);
			} else {
				logger.info("Error testing connection; " + this.tmp_token);
				errorMessage = "Error testing connection; Server returned: " + response.getStatusLine().getStatusCode()
						+ "; "
						+ " Invalid inputs or something went wrong with server. Please check API server and/or proxy details.";
				throw new Exception(errorMessage);
			}

		} catch (SocketException e) {
			errorMessage = "Error testing connection; SocketException; Invalid inputs or something went wrong with server. Please check API server and/or proxy details.";
			throw new Exception(errorMessage);
		} catch (Exception e) {
			throw new Exception(errorMessage);
		}
	}

	private CloseableHttpResponse getAuthToken() throws Exception {
		logger.info("Generating Auth Token...");
		String output_msg = "";
		int timeInterval = 0;
		CloseableHttpResponse response = null;
		while (timeInterval < this.retryCount) {
			output_msg = "";
			try {
				response = this.postTestConnection(this.apiMap.get("getAuth"));
				if (response.getEntity() != null) {
					BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
					String output;
					while ((output = br.readLine()) != null) {
						output_msg += output;
					}
				}
				this.tmp_token = output_msg;
				logger.info("Fetching auth token: Response code: " + response.getStatusLine().getStatusCode());
				break;
			} catch (SocketException e) {
				logger.info("SocketException : " + e);
				throw e;
			} catch (IOException e) {
				logger.info("IOException : " + e);
				throw e;
			} catch (Exception e) {
				logger.info("Exception : " + e);

				// Handling Empty response and empty response code here
				timeInterval++;
				if (timeInterval < this.retryCount) {
					try {
						logger.info("Retry fetching auth token ...");
						Thread.sleep(this.retryInterval * 1000);
					} catch (Exception e1) {
						logger.info("Exception : " + e1);
						throw e1;
					}
				} else {
					throw e;
				}

			}
		}
		return response;
	}

	private boolean validateSubscription(String jwt) {
		String[] jwtToken = jwt.split("\\.");
		Base64.Decoder decoder = Base64.getDecoder();
		String djwtToken = new String(decoder.decode(jwtToken[1]));
		Gson gson = new Gson();
		JsonObject decodedjwtToken = gson.fromJson(djwtToken, JsonObject.class);
		if (decodedjwtToken.has("modulesAllowed")) {
			if (decodedjwtToken.get("modulesAllowed").toString().contains("\"PC\"")) {
				logger.info("PC Module Found");
				return true;
			}
		}
		logger.info("PC Module Not Found");
		return false;
	}

	private CloseableHttpResponse postTestConnection(String apiPath) throws Exception {
		CloseableHttpResponse response = null;
		try {
			URL url = this.getAbsoluteUrlForTestConnection(apiPath);
			logger.info("Making Request To: " + url.toString());
			CloseableHttpClient httpclient = this.getHttpClient();
			HttpPost postRequest = new HttpPost(url.toString());
			postRequest.addHeader("accept", "application/json");
			postRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");
			byte[] bb = this.getJWTAuthHeader();
			ByteArrayEntity br = new ByteArrayEntity(bb);
			postRequest.setEntity(br);
			logger.info("JWT Auth Header Request To: " + br.getContent().toString());
			response = httpclient.execute(postRequest);
			logger.info("Post request status: " + response.getStatusLine().getStatusCode());
		} catch (Exception e) {
			throw e;
		}
		return response;
	}

	public JsonObject getConnector() throws Exception {
		logger.info("Connector Name is accepted and getting the DOC.");
		NodeList dataList = null;
		Document response = null;
		JSONObject connetorList = new JSONObject();
		JSONObject cList = new JSONObject();
		JsonParser jsonParser = new JsonParser();
		QualysPCResponse resp = new QualysPCResponse();
		String name = "";
		int retry = 0;
		try {
			while (retry < 3) {
				logger.info("Retrying Connector Name API call: " + retry);
				resp = this.post(this.apiMap.get("getConnector"), "", "");
				logger.info("Response code received for Connector Name API call:" + resp.getResponseCode());
				response = resp.getResponseXml();
				if (resp != null && resp.getResponseCode() == 200) {
					NodeList responseCode = response.getElementsByTagName("responseCode");
					if (responseCode.item(0).getTextContent().equalsIgnoreCase("SUCCESS")) {
						NodeList applinaceList = response.getElementsByTagName("AwsAssetDataConnector");
						logger.info("Connector List lenght - " + String.valueOf(applinaceList.getLength()));
						for (int temp = 0; temp < applinaceList.getLength(); temp++) {
							Node nNode = applinaceList.item(temp);
							if (nNode.getNodeType() == Node.ELEMENT_NODE) {
								Element eElement = (Element) nNode;
								// Populate all the connectors
								if (!(eElement.getElementsByTagName("name").getLength() > 0)) {
									name = "Unknown";
								} else {
									name = eElement.getElementsByTagName("name").item(0).getTextContent();
								}
								if (!(eElement.getElementsByTagName("id").getLength() > 0)) {
									cList.put("id", "Unknown");
								} else {
									cList.put("id", eElement.getElementsByTagName("id").item(0).getTextContent());
								}
								if (!(eElement.getElementsByTagName("connectorState").getLength() > 0)) {
									cList.put("connectorState", "Unknown");
								} else {
									cList.put("connectorState",
											eElement.getElementsByTagName("connectorState").item(0).getTextContent());
								}
								if (!(eElement.getElementsByTagName("awsAccountId").getLength() > 0)) {
									cList.put("awsAccountId", "Unknown");
								} else {
									cList.put("awsAccountId",
											eElement.getElementsByTagName("awsAccountId").item(0).getTextContent());
								}

								connetorList.accumulate(name, cList);
								cList = new JSONObject();
							} // End of if
						}
						jsonParser = new JsonParser();
					} else {
						NodeList responseErrorDetails = response.getElementsByTagName("responseErrorDetails");
						if (responseErrorDetails != null) {
							for (int tempE = 0; tempE < responseErrorDetails.getLength(); tempE++) {
								Node nNodeE = responseErrorDetails.item(tempE);
								if (nNodeE.getNodeType() == Node.ELEMENT_NODE) {
									Element eError = (Element) nNodeE;
									if ((eError.getElementsByTagName("errorMessage").getLength() > 0)
											|| (eError.getElementsByTagName("errorResolution").getLength() > 0)) {
										throw new Exception(
												"Error while getting the Connector names. API Error Message: "
														+ eError.getElementsByTagName("errorMessage").item(0)
																.getTextContent()
														+ " | API Error Resolution: "
														+ eError.getElementsByTagName("errorResolution").item(0)
																.getTextContent());
									}
								}
							}
						}
					}
					break;
				} else {
					retry++;
					dataList = response.getElementsByTagName("responseErrorDetails");
					for (int temp = 0; temp < dataList.getLength(); temp++) {
						Node nNode = dataList.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eError = (Element) nNode;
							if ((eError.getElementsByTagName("errorMessage").getLength() > 0)
									|| (eError.getElementsByTagName("errorResolution").getLength() > 0)) {
								throw new Exception("Error in getting Connector names. API Error Message: "
										+ eError.getElementsByTagName("errorMessage").item(0).getTextContent()
										+ " | API Error Resolution: "
										+ eError.getElementsByTagName("errorResolution").item(0).getTextContent());
							}
						}
					}
				}
			}
		} catch (Exception e) {
			if (e.getMessage() == null) {
				throw new Exception(exceptionWhileToget + " the Connector name list." + responseCode
						+ resp.getResponseCode() + nullMessage);
			} else {
				throw new Exception(e.getMessage());
			}
		}
		return (JsonObject) jsonParser.parse(connetorList.toString());
	}// End of getConnector

	public JsonObject runConnector(String connId) throws Exception {
		logger.info("Running the connector with Id:" + connId);
		NodeList dataList = null;
		Document response = null;
		JsonObject connectorState = new JsonObject();
		QualysPCResponse resp = new QualysPCResponse();
		int retry = 0;
		connectorState.addProperty("request", "");
		connectorState.addProperty("connectorState", "");

		try {
			while (retry < 3) {
				logger.info("Retrying run Connector API call: " + retry);
				resp = this.post(this.apiMap.get("runConnector") + "/" + connId, "", "");
				logger.info("Response code received for run Connector API call:" + resp.getResponseCode());
				response = resp.getResponseXml();
				connectorState.addProperty("request", resp.getRequest());
				if (resp != null && resp.getResponseCode() == 200) {
					NodeList applinaceList = response.getElementsByTagName("AwsAssetDataConnector");
					for (int temp = 0; temp < applinaceList.getLength(); temp++) {
						Node nNode = applinaceList.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eElement = (Element) nNode;
							if (!(eElement.getElementsByTagName("connectorState").getLength() > 0)) {
								connectorState.addProperty("connectorState", "Unknown");
							} else {
								connectorState.addProperty("connectorState",
										eElement.getElementsByTagName("connectorState").item(0).getTextContent());
							}
						} // End of if
					}
					break;
				} else {
					retry++;
					dataList = response.getElementsByTagName("responseErrorDetails");
					for (int temp = 0; temp < dataList.getLength(); temp++) {
						Node nNode = dataList.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eError = (Element) nNode;
							if ((eError.getElementsByTagName("errorMessage").getLength() > 0)
									|| (eError.getElementsByTagName("errorResolution").getLength() > 0)) {
								throw new Exception("Error in running Connector. API Error Message: "
										+ eError.getElementsByTagName("errorMessage").item(0).getTextContent()
										+ " | API Error Resolution: "
										+ eError.getElementsByTagName("errorResolution").item(0).getTextContent());
							}
						}
					}
				}
			}
		} catch (Exception e) {
			logger.info("Exception while running the connector. Error: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			if (e.getMessage() == null) {
				throw new Exception(
						exceptionWhileTorun + " the Connector." + responseCode + resp.getResponseCode() + nullMessage);
			} else {
				throw new Exception(e.getMessage());
			}
		}
		return connectorState;
	}// End of runConnector

	public JsonObject getConnectorStatus(String connId2) throws Exception {
		logger.info("Getting the connector status for Id:" + connId2);
		NodeList dataList = null;
		Document response = null;
		JsonObject connectorState = new JsonObject();
		connectorState.addProperty("request", "");
		QualysPCResponse resp = new QualysPCResponse();
		int retry = 0;
		try {
			while (retry < 3) {
				logger.info("Retrying to get the Connector Status API call: " + retry);
				resp = this.get(this.apiMap.get("getConnectorStatus") + "/" + connId2, false);
				logger.info("Response code received for run Connector API call:" + resp.getResponseCode());
				response = resp.getResponseXml();
				connectorState.addProperty("request", resp.getRequest());
				if (resp != null && resp.getResponseCode() == 200) {
					NodeList applinaceList = response.getElementsByTagName("AssetDataConnector");
					for (int temp = 0; temp < applinaceList.getLength(); temp++) {
						Node nNode = applinaceList.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eElement = (Element) nNode;
							if (!(eElement.getElementsByTagName("connectorState").getLength() > 0)) {
								connectorState.addProperty("connectorState", "Unknown");
							} else {
								connectorState.addProperty("connectorState",
										eElement.getElementsByTagName("connectorState").item(0).getTextContent());
							}
						} // End of if
					}
					break;
				} else {
					retry++;
					dataList = response.getElementsByTagName("responseErrorDetails");
					for (int temp = 0; temp < dataList.getLength(); temp++) {
						Node nNode = dataList.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eError = (Element) nNode;
							if ((eError.getElementsByTagName("errorMessage").getLength() > 0)
									|| (eError.getElementsByTagName("errorResolution").getLength() > 0)) {
								throw new Exception("Error in getting Connector state. API Error Message: "
										+ eError.getElementsByTagName("errorMessage").item(0).getTextContent()
										+ " | API Error Resolution: "
										+ eError.getElementsByTagName("errorResolution").item(0).getTextContent());
							}
						}
					}
				}
			}
		} catch (Exception e) {
			logger.info("Exception while getting the connector state. Error: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			if (e.getMessage() == null) {
				throw new Exception(exceptionWhileToget + " the Connector state." + responseCode
						+ resp.getResponseCode() + nullMessage);
			} else {
				throw new Exception(e.getMessage());
			}
		}
		logger.info("Current Connector State is: " + connectorState);
		return connectorState;
	}// End of getConnectorStatus

	public JsonObject getInstanceState(String ec2Id, String accountId) throws Exception {
		logger.info("Getting the instance state for Id:" + ec2Id);
		NodeList dataList = null;
		Document response = null;
		JsonObject state = new JsonObject();
		state.addProperty("instanceState", "");
		state.addProperty("endpoint", "");
		state.addProperty("count", "Unknown");
		state.addProperty("request", "");
		state.addProperty("requestBody", "");
		state.addProperty("requestParam", "");

		QualysPCResponse resp = new QualysPCResponse();
		int retry = 0;
		String xmlReqData = "<ServiceRequest> <filters> " + "<Criteria field=\"instanceId\" operator=\"EQUALS\">"
				+ ec2Id + "</Criteria> " + "<Criteria field=\"accountId\" operator=\"EQUALS\">" + accountId
				+ "</Criteria> " + "</filters> </ServiceRequest>";
		try {
			while (retry < 3) {
				logger.info("Retrying to get the instance state API call: " + retry);
				resp = this.post(this.apiMap.get("getInstanceState"), "", xmlReqData);
				logger.info("Response code received for instance state API call:" + resp.getResponseCode());
				response = resp.getResponseXml();
				state.addProperty("request", resp.getRequest());
				state.addProperty("requestBody", resp.getRequestBody());
				state.addProperty("requestParam", resp.getRequestParam());

				if (resp != null && resp.getResponseCode() == 200) {
					NodeList serviceResponse = response.getElementsByTagName("ServiceResponse");
					NodeList applinaceList = response.getElementsByTagName("Ec2AssetSourceSimple");
					for (int temp = 0; temp < serviceResponse.getLength(); temp++) {
						Node nNode = serviceResponse.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eElement = (Element) nNode;
							if (!(eElement.getElementsByTagName("responseCode").item(0).getTextContent()
									.equalsIgnoreCase("SUCCESS"))) {
								state.addProperty("apiError",
										eElement.getElementsByTagName("responseCode").item(0).getTextContent());
							} else if (eElement.getElementsByTagName("count").getLength() > 0) {
								state.addProperty("count", Integer
										.parseInt(eElement.getElementsByTagName("count").item(0).getTextContent()));
							}
						} // End of if
					}

					for (int temp = 0; temp < applinaceList.getLength(); temp++) {
						Node nNode = applinaceList.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eElement = (Element) nNode;
							if (!(eElement.getElementsByTagName("instanceState").getLength() > 0)) {
								state.addProperty("instanceState", "Unknown");

							} else {
								state.addProperty("instanceState",
										eElement.getElementsByTagName("instanceState").item(0).getTextContent());
							}
							if (!(eElement.getElementsByTagName("region").getLength() > 0)) {
								state.addProperty("endpoint", "Unknown");
							} else {
								state.addProperty("endpoint",
										eElement.getElementsByTagName("region").item(0).getTextContent());
							}
							if (!(eElement.getElementsByTagName("privateIpAddress").getLength() > 0)) {
								state.addProperty("ec2PrivateIpAddress", "Unknown");
							} else {
								state.addProperty("ec2PrivateIpAddress",
										eElement.getElementsByTagName("privateIpAddress").item(0).getTextContent());
							}
						} // End of if
					}
					break;
				} else {
					retry++;
					dataList = response.getElementsByTagName("responseErrorDetails");
					for (int temp = 0; temp < dataList.getLength(); temp++) {
						Node nNode = dataList.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eError = (Element) nNode;
							if ((eError.getElementsByTagName("errorMessage").getLength() > 0)
									|| (eError.getElementsByTagName("errorResolution").getLength() > 0)) {
								throw new Exception("Error in getting Instance state. API Error Message: "
										+ eError.getElementsByTagName("errorMessage").item(0).getTextContent()
										+ " | API Error Resolution: "
										+ eError.getElementsByTagName("errorResolution").item(0).getTextContent());
							}
						}
					}
				}
			}
		} catch (Exception e) {
			logger.info("Exception while getting the Instance state. Error: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			if (e.getMessage() == null) {
				throw new Exception(exceptionWhileToget + " the Instance state." + responseCode + resp.getResponseCode()
						+ nullMessage);
			} else {
				throw new Exception(e.getMessage());
			}
		}
		if (state.has("instanceState") && state.get("instanceState").getAsString().isEmpty())
			state.addProperty("instanceState", "Unknown");
		if (state.has("endpoint") && state.get("endpoint").getAsString().isEmpty())
			state.addProperty("endpoint", "Unknown");
		return state;
	}// End of getInstanceState

	// End of API calling methods

	// Do a [GET] call
	private QualysPCResponse get(String apiPath, Boolean getJson) throws Exception {
		QualysPCResponse apiResponse = new QualysPCResponse();
		String apiResponseString = "";
		CloseableHttpClient httpclient = null;

		try {
			URL url = this.getAbsoluteUrl(apiPath);
			String making = "Making GET Request: " + url.toString();
			this.stream.println(making);
			apiResponse.setRequest(making);
			httpclient = this.getHttpClient();

			HttpGet getRequest = new HttpGet(url.toString());
			getRequest.addHeader("Content-Type", "text/xml");
			getRequest.addHeader("X-Requested-With", "Qualys");
			getRequest.addHeader("Accept-Charset", "iso-8859-1, unicode-1-1;q=0.8");
			getRequest.addHeader("Authorization", "Basic " + this.getBasicAuthHeader());

			CloseableHttpResponse response = httpclient.execute(getRequest);
			apiResponse.setResponseCode(response.getStatusLine().getStatusCode());
			logger.info("Server returned with ResponseCode: " + apiResponse.getResponseCode());
			if (apiResponse.getResponseCode() == 401) {
				throw new Exception("ACCESS DENIED");
			}
			// Handling the concurrent api limit reached case
			else if (apiResponse.getResponseCode() == 409) {
				long startTime = System.currentTimeMillis();
				long vulnsTimeoutInMillis = TimeUnit.SECONDS.toMillis(120);
				long pollingInMillis = TimeUnit.SECONDS.toMillis(2);

				while (apiResponse.getResponseCode() == 409) {

					long endTime = System.currentTimeMillis();
					if ((endTime - startTime) > vulnsTimeoutInMillis) {
						logger.info("Timeout of " + TimeUnit.SECONDS.toMinutes(120) + " minutes reached.");
						throw new Exception(exceptionWhileTorun + " QualysPCResponse GET method." + responseCode
								+ apiResponse.getResponseCode() + conRefuse);

					}

					logger.info("Concurrent API Limit is reached, retrying in every 2 seconds");
					Thread.sleep(pollingInMillis);

					httpclient = null;
					response = null;
					httpclient = this.getHttpClient();
					response = httpclient.execute(getRequest);
					apiResponse.setResponseCode(response.getStatusLine().getStatusCode());
					logger.info("Server returned with ResponseCode: " + apiResponse.getResponseCode());

				}

			} else if (apiResponse.getResponseCode() != 200) {
				throw new Exception(exceptionWhileTorun + " QualysPCResponse GET method." + responseCode
						+ apiResponse.getResponseCode() + conRefuse);
			}
			if (response.getEntity() != null) {
				if (getJson) {
					Gson gson = new Gson();
					apiResponseString = getresponseString(response);
					JsonArray jsonArray = gson.fromJson(apiResponseString, JsonArray.class);
					JsonObject finalResult = new JsonObject();
					finalResult.add("data", jsonArray);
					if (!finalResult.isJsonObject()) {
						throw new APIResponseException("apiResponseString is not a Json Object");
					}
					apiResponse.setResponse(finalResult.getAsJsonObject());
				} else {
					apiResponse.setResponseXml(getDoc(response));
				} // End of inner if-else
			} // End of If
		} catch (SocketException e) {
			String errorMessage = "Error testing connection; SocketException; Invalid inputs or something went wrong with server. Please check API server and/or proxy details.";
			logger.info(errorMessage+ " "+ e.getMessage());
			throw new Exception(errorMessage);
		} catch (JsonParseException je) {
			apiResponse.setErrored(true);
			apiResponse.setErrorMessage(apiResponseString);
		} catch (AbortException e) {
			apiResponse.setErrored(true);
			apiResponse.setErrorMessage(e.getMessage());
			if (e.getMessage() == null) {
				throw new Exception(exceptionWhileTorun + " Qualys PC Response POST method." + responseCode
						+ apiResponse.getResponseCode() + nullMessage);
			} else {
				throw new Exception(e.getMessage());
			}
		} catch (Exception e) {
			apiResponse.setErrored(true);
			apiResponse.setErrorMessage(e.getMessage());
			if (e.getMessage() == null) {
				throw new Exception(exceptionWhileTorun + " Qualys PC Response GET method." + responseCode
						+ apiResponse.getResponseCode() + nullMessage);
			} else {
				throw new Exception(e.getMessage());
			}
		} // End of catch
		return apiResponse;
	} // End of QualysPCResponse get() method

	// Do a [POST] call
	private QualysPCResponse post(String apiPath, String requestData, String requestXmlString) throws Exception {
		QualysPCResponse apiResponse = new QualysPCResponse();
		String apiResponseString = "";
		CloseableHttpClient httpclient = null;
		String uri = null;

		try {
			URL url = this.getAbsoluteUrl(apiPath);
			if (!requestData.isEmpty()) {
				uri = url.toString() + "&" + requestData;
				apiResponse.setRequestParam(requestXmlString);
			} else {
				uri = url.toString();
			}
			String link = uri.toString();
			if (link.indexOf("password") != -1) {
				link = link.replaceAll("password=.*&", "password=*****&");
			}

			if (listener != null) {
				listener.getLogger().println("Making POST Request: " + link);
			}

			logger.info("Making POST Request: " + link);
			apiResponse.setRequest(uri.toString());
			httpclient = this.getHttpClient();
			HttpPost postRequest = new HttpPost(uri.toString());
			postRequest.addHeader("accept", "application/xml");
			postRequest.addHeader("X-Requested-With", "Qualys");
			postRequest.addHeader("Authorization", "Basic " + this.getBasicAuthHeader());

			if (requestXmlString != null && !requestXmlString.isEmpty()) {
				logger.info("POST Request body: " + requestXmlString);
				apiResponse.setRequestBody(requestXmlString);
				postRequest.addHeader("Content-Type", "application/xml");
				HttpEntity entity = new ByteArrayEntity(requestXmlString.getBytes("UTF-8"));
				postRequest.setEntity(entity);
			}
			CloseableHttpResponse response = httpclient.execute(postRequest);
			apiResponse.setResponseCode(response.getStatusLine().getStatusCode());
			if (listener != null)
				listener.getLogger().println("Server returned with ResponseCode:" + apiResponse.getResponseCode());
			logger.info("Server returned with ResponseCode:" + apiResponse.getResponseCode());
			if (apiResponse.getResponseCode() == 401) {
				throw new Exception("ACCESS DENIED");
			}
			// Handling the concurrent api limit reached case
			else if (apiResponse.getResponseCode() == 409) {
				long startTime = System.currentTimeMillis();
				long vulnsTimeoutInMillis = TimeUnit.SECONDS.toMillis(vulnsTimeout);
				long pollingInMillis = TimeUnit.SECONDS.toMillis(pollingIntervalForVulns);

				while (apiResponse.getResponseCode() == 409) {

					long endTime = System.currentTimeMillis();
					if ((endTime - startTime) > vulnsTimeoutInMillis) {
						logger.info("Timeout of " + TimeUnit.SECONDS.toMinutes(vulnsTimeout) + " minutes reached.");
						throw new Exception(exceptionWhileTorun + " QualysPCResponse POST method." + responseCode
								+ apiResponse.getResponseCode() + conRefuse);

					}

					Thread.sleep(pollingInMillis);
					if (listener != null)
						listener.getLogger().println("Concurrent API Limit is reached, retrying in every "
								+ String.valueOf(pollingIntervalForVulns) + " seconds");

					httpclient = null;
					response = null;
					httpclient = this.getHttpClient();
					response = httpclient.execute(postRequest);
					apiResponse.setResponseCode(response.getStatusLine().getStatusCode());
					if (listener != null)
						listener.getLogger()
								.println("Server returned with ResponseCode: " + apiResponse.getResponseCode());

				}

			}
			// change end
			else if (apiResponse.getResponseCode() != 200) {
				throw new Exception(exceptionWhileTorun + " QualysPCResponse POST method." + responseCode
						+ apiResponse.getResponseCode() + conRefuse);
			}
			if (response.getEntity() != null) {
				apiResponse.setResponseXml(getDoc(response));
			} // End of If
		} catch (JsonParseException je) {
			apiResponse.setErrored(true);
			apiResponse.setErrorMessage(apiResponseString);
		} catch (AbortException e) {
			apiResponse.setErrored(true);
			apiResponse.setErrorMessage(e.getMessage());
			if (e.getMessage() == null) {
				throw new Exception(exceptionWhileTorun + " Qualys PC Response POST method." + responseCode
						+ apiResponse.getResponseCode() + nullMessage);
			} else {
				throw new Exception(e.getMessage());
			}
		} catch (Exception e) {
			apiResponse.setErrored(true);
			apiResponse.setErrorMessage(e.getMessage());
			if (e.getMessage() == null) {
				throw new Exception(exceptionWhileTorun + " Qualys PC Response POST method." + responseCode
						+ apiResponse.getResponseCode() + nullMessage);
			} else {
				throw new Exception(e.getMessage());
			}
		}
		return apiResponse;
	}// End of QualysPCResponse post() method

	public Set<String> optionProfilesSet(Document resp, int respCode, String apiTypeName) throws Exception {
		Set<String> nameList = new HashSet<>();
		NodeList opList = resp.getElementsByTagName("OPTION_PROFILE");
		logger.info(apiTypeName + " list lenght - " + String.valueOf(opList.getLength()));
		try {
			for (int i = 0; i < opList.getLength(); i++) {
				Node nNode = opList.item(i);
				if (nNode.getNodeType() == Node.ELEMENT_NODE) {
					Element eElement = (Element) nNode;

					// Checking is policies which are create only for jenkins plugin. Profile name
					// should start with Jenkins_
					String str = eElement.getElementsByTagName("GROUP_NAME").item(0).getTextContent();
					if (str.startsWith("Jenkins_")) {
						nameList.add(eElement.getElementsByTagName("GROUP_NAME").item(0).getTextContent() + ":"
								+ eElement.getElementsByTagName("ID").item(0).getTextContent());
					}
				} // End of if
			} // End of outer for loop
		} catch (Exception e) {
			if (e.getMessage() == null) {
				throw new Exception(
						exceptionWhileToget + " option Profiles Set." + responseCode + respCode + nullMessage);
			} else {
				throw new Exception(exceptionWhileToget + " option Profiles Set." + responseCode + respCode + " Error: "
						+ e.getMessage());
			}
		}
		return nameList;
	}// End of optionProfilesSet method

	private QualysPCResponse getList(int retry, String apiTypeName, String api) throws Exception {
		// Set<String> opList = new HashSet<>();
		QualysPCResponse resp = new QualysPCResponse();
		try {
			while (retry < 3) {
				logger.info("Retrying " + apiTypeName + " API call: " + retry);
				resp = this.get(this.apiMap.get(api), false);
				logger.info("Response code received while getting the " + apiTypeName + " API call:"
						+ resp.getResponseCode());

				if (resp != null && resp.getResponseCode() == 200) {
					break;
				} else if (resp.getResponseCode() == 401) {
					throw new Exception("ACCESS DENIED");
				} else if (resp.getResponseCode() != 200) {
					throw new Exception(exceptionWhileToget + " the " + apiTypeName + " list." + responseCode
							+ resp.getResponseCode() + conRefuse);
				} else {
					retry++;
					NodeList dataList = resp.getResponseXml().getElementsByTagName("RESPONSE");
					for (int temp = 0; temp < dataList.getLength(); temp++) {
						Node nNode = dataList.item(temp);
						if (nNode.getNodeType() == Node.ELEMENT_NODE) {
							Element eElement = (Element) nNode;
							throw new Exception(apiTypeName + " API Error code: "
									+ eElement.getElementsByTagName("CODE").item(0).getTextContent()
									+ " | API Error message: "
									+ eElement.getElementsByTagName("TEXT").item(0).getTextContent());
						}
					}
				} // End of if else
			} // End of while
		} catch (Exception e) {
			if (e.getMessage() == null) {
				throw new Exception(exceptionWhileToget + " the " + apiTypeName + " list." + responseCode
						+ resp.getResponseCode() + nullMessage);
			} else {
				throw new Exception(exceptionWhileToget + " the " + apiTypeName + " list." + responseCode
						+ resp.getResponseCode() + " " + e.getMessage());
			}
		}
		return resp;
	}// end of getList method

	private JsonObject getScannerDetails(Document response, boolean ec2) {
		String accountId = "";
		String name = "";
		String status = "";
		JSONObject scannerObj = new JSONObject();
		JSONObject scannerList = new JSONObject();
		try {
			NodeList applinaceList = response.getElementsByTagName("APPLIANCE");
			logger.info("Scanner List lenght - " + String.valueOf(applinaceList.getLength()));
			for (int temp = 0; temp < applinaceList.getLength(); temp++) {
				Node nNode = applinaceList.item(temp);
				if (nNode.getNodeType() == Node.ELEMENT_NODE) {
					Element eElement = (Element) nNode;
					name = eElement.getElementsByTagName("NAME").item(0).getTextContent();
					status = eElement.getElementsByTagName("STATUS").item(0).getTextContent();
					if (ec2) {
						NodeList endpoint0 = eElement.getElementsByTagName("CLOUD_INFO");
						for (int temp0 = 0; temp0 < endpoint0.getLength(); temp0++) {
							Node nNode0 = endpoint0.item(temp0);
							if (nNode0.getNodeType() == Node.ELEMENT_NODE) {
								Element epElement0 = (Element) nNode0;
								accountId = epElement0.getElementsByTagName("ACCOUNT_ID").item(0).getTextContent();
							} // End of endpoint if
						} // End of endpoint for loop
					} // end of ec2 if
					scannerList.accumulate("status", status);
					scannerList.accumulate("accountId", accountId);
					scannerObj.accumulate(name, scannerList);
					scannerList = new JSONObject();
				} // End of if
			} // end of for
		} catch (Exception e) {
			throw e;
		}
		JsonParser jsonParser = new JsonParser();
		return (JsonObject) jsonParser.parse(scannerObj.toString());
	}// end of getScannerDetails method

	public String getTextValueOfXml(Document doc, String topNode, String topPath, String innerNode, String innerPath,
			String message) throws Exception {
		String topResponseString = "Unknown";
		String innerResponseString = "Unknown";
		try {
			NodeList topList = doc.getElementsByTagName(topNode);
			for (int i = 0; i < topList.getLength(); i++) {
				Node tNode = topList.item(i);
				if (tNode.getNodeType() == Node.ELEMENT_NODE) {
					Element topElement = (Element) tNode;
					if (topElement.getElementsByTagName(topPath).getLength() > 0) {
						topResponseString = topElement.getElementsByTagName(topPath).item(0).getTextContent();
					}
					if (!innerNode.isEmpty()) {
						NodeList innerList = topElement.getElementsByTagName(innerNode);
						for (int j = 0; j < innerList.getLength(); j++) {
							Node iNode = innerList.item(j);
							if (iNode.getNodeType() == Node.ELEMENT_NODE) {
								Element element = (Element) iNode;
								if (element.getElementsByTagName(innerPath).getLength() > 0) {
									innerResponseString = topElement.getElementsByTagName(innerPath).item(0)
											.getTextContent();
								}
							}
						}
					}
				}
			}
		} catch (Exception e) {
			logger.info("Exception while getting the text value of XML. Error: " + e.getMessage());
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			throw e;
		}
		if (!innerNode.isEmpty()) {
			return innerResponseString;
		} else {
			return topResponseString;
		}
	}// End of getTextValueOfXml String

	private Document getDoc(CloseableHttpResponse response) throws Exception {
		String apiResponseString = "";
		Document doc = null;
		try {
			apiResponseString = getresponseString(response);
			if (!apiResponseString.contains("<?xml")) {
				throw new APIResponseException("apiResponseString is not proper XML.");
			}
			// Parse the XML response to XML Document
//	            logger.info(apiResponseString);
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			try {
				factory.setValidating(false);
				factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
			} catch (ParserConfigurationException ex) {
				logger.info(
						"Exception for XML external entity while getting Document. Reason: " + ex.getMessage() + "\n");
				return doc;
			}
			DocumentBuilder builder = factory.newDocumentBuilder();
			ByteArrayInputStream input = new ByteArrayInputStream(apiResponseString.toString().getBytes("UTF-8"));
			doc = builder.parse(input);
			doc.getDocumentElement().normalize();
			logger.info("Root element :" + doc.getDocumentElement().getNodeName());
		} catch (Exception e) {
			String error = "Exception while getting Document. Reason: " + e.getMessage() + "\n";
			logger.info(error);
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			throw new Exception(error);
		}
		return doc;
	}// end of getDoc method

	private String getresponseString(CloseableHttpResponse response) throws Exception {
		String apiResponseString = "";
		try {
			BufferedReader br = new BufferedReader(
					new InputStreamReader(response.getEntity().getContent(), "iso-8859-1"));
			String output;
			while ((output = br.readLine()) != null) {
				apiResponseString += output;
			}
		} catch (Exception e) {
			String error = "Exception while getting response String. Error: " + e.getMessage();
			logger.info(error);
			for (StackTraceElement traceElement : e.getStackTrace())
				logger.info("\tat " + traceElement);
			throw new Exception(error);
		}
		return apiResponseString;
	}
} // end of QualysPCClient Class