package com.qualys.plugins.pc;

import java.io.PrintStream;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.qualys.plugins.pc.auth.QualysAuth;
import com.qualys.plugins.pc.client.APIResponseException;
import com.qualys.plugins.pc.client.QualysPCClient;
import com.qualys.plugins.pc.util.Helper;
import com.qualys.plugins.pc.util.TimeOutException;
import hudson.AbortException;
import hudson.model.Run;
import hudson.model.TaskListener;

public class PCScanEc2ConnectorLauncher {	
    private PrintStream buildLogger;
    private String connId;
    private String ec2ConnName;    
    private int pollingIntervalForVulns;
    private int vulnsTimeout;    
    private QualysPCClient apiClient;	
    private final static Logger logger = Helper.getLogger(PCScanLauncher.class.getName());
    private final static int DEFAULT_POLLING_INTERVAL_FOR_VULNS = 2; //2 minutes
    private final static int DEFAULT_TIMEOUT_FOR_VULNS = 60; //1Hrs
    private List<String> errorList;
    private List<String> successList;
    
    public PCScanEc2ConnectorLauncher(Run<?, ?> run, TaskListener listener,  
    		String pollingIntervalStr, String vulnsTimeoutStr, QualysAuth auth, 
    		boolean useEc2, String connId, String ec2ConnName) {    	
        this.buildLogger = listener.getLogger();
        this.connId = connId;
        this.ec2ConnName = ec2ConnName;
    	this.apiClient = new QualysPCClient(auth, System.out);        
        this.pollingIntervalForVulns = setTimeoutInMinutes("pollingInterval", DEFAULT_POLLING_INTERVAL_FOR_VULNS, pollingIntervalStr, listener);
		this.vulnsTimeout = setTimeoutInMinutes("vulnsTimeout", DEFAULT_TIMEOUT_FOR_VULNS, vulnsTimeoutStr, listener);
		errorList = new ArrayList<String>();		
		errorList.add("FINISHED_ERRORS");
		errorList.add("ERROR");    	
		errorList.add("INCOMPLETE");
		errorList.add("DISABLED");
		successList = new ArrayList<String>();
		successList.add("FINISHED_SUCCESS");
		successList.add("SUCCESS");
    } // end of Xtor
    
    private int setTimeoutInMinutes(String timeoutType, int defaultTimeoutInMins, String timeout, TaskListener listener) {    	   	
    	if (!(timeout == null || timeout.isEmpty()) ){
    		try {
    			//calculate the timeout in seconds
    			String[] numbers = timeout.split("\\*");
    			int timeoutInMins = 1;
    			for (int i = 0; i<numbers.length ; ++i) {
    				timeoutInMins *= Long.parseLong(numbers[i]);
    			}    			
    			return timeoutInMins;
    		} catch(Exception e) {
    			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Invalid " + timeoutType + " time value. Cannot parse -"+e.getMessage() + "\n"+new Timestamp(System.currentTimeMillis())+" Using default period of " + (timeoutType.equals("vulnsTimeout") ? "60" : defaultTimeoutInMins) + " minutes for " + timeoutType + ".");
    			for (StackTraceElement traceElement : e.getStackTrace())
	                logger.info("\tat " + traceElement);    			    			
    		}
    	}
    	return defaultTimeoutInMins; 
    }
    
    /*This method is called in the launchHostScan method under PCScanNotifiers class*/
   	@SuppressWarnings("null")
	public void runCtor() throws Exception {   		
       	try {
       		JsonObject connectorRunState = apiClient.runConnector(connId);
       		JsonElement connectorState = connectorRunState.get("connectorState");
       		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Making GET Request: " + connectorRunState.get("request").getAsString());
       		buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Current connector state is: " + connectorRunState.get("connectorState").getAsString());
       		if (connectorState != null  && !connectorState.isJsonNull() && !connectorState.getAsString().isEmpty()) {       			
       			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Polling started!");
       			ctorPolling(connId, false);
			} else {   			
				throw new Exception("API error. Could not run the connector.");
			}
       	} catch (AbortException e) {
       		logger.info("AbortException while running connector. " + e.getMessage());
       		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);       		
       		throw new AbortException(e.getMessage());
       	} catch (Exception e) {
       		logger.info("Exception while running connector. " + e.getMessage());
       		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);       		
       		throw new Exception(e.getMessage());
       	}       	
    }// End of getAndProcessLaunchScanResult method
   	
   	public void ctorPolling(String connId, boolean sendToNotifier) throws Exception {
   		String runStatus = null;
   		long startTime = System.currentTimeMillis();
    	long vulnsTimeoutInMillis = TimeUnit.MINUTES.toMillis(vulnsTimeout);
    	long pollingInMillis = TimeUnit.MINUTES.toMillis(pollingIntervalForVulns);    	    	
   		try {
	    	while ((runStatus = getCtorStatus(connId, sendToNotifier)) == null) {	    		
	    		long endTime = System.currentTimeMillis();
	    		if ((endTime - startTime) > vulnsTimeoutInMillis) {
	    			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Failed to get state result; timeout of " + vulnsTimeout + " minutes reached.");    			
	    			throw new TimeOutException("Timeout reached.");	    			
	    		}       		    		
	    		if (runStatus == null) {
	    			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Waiting for " + pollingIntervalForVulns + " minute(s) before making next attempt for connector state of " + this.ec2ConnName + "(" +this.connId+")");
    			Thread.sleep(pollingInMillis);
	    		}	    		
	    	}
	    	if (runStatus != null && errorList.contains(runStatus)) {
	    		throw new AbortException("Aborting the build as the connector ("+ec2ConnName+") state is: " + runStatus);
        	}
    	}catch (TimeOutException e) {
    		String error = " Exception: Timeout reached.";
    		buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
    		logger.info(error);
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);    		
    		throw e;
    	}       	    	
		catch(Exception e) {
			String error = " Build Aborted!!\n";
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
			logger.info(error);
			for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);			
			throw e;
		}   		
   	}
   	
   	public String getCtorStatus(String connId2, boolean sendToNotifier) {
   		JsonObject connectorState = null;   		
   		String connectorStatus = null;
   		
		try {
			connectorState = apiClient.getConnectorStatus(connId2);
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " " + connectorState.get("request").getAsString());
			JsonElement ctorState = connectorState.get("connectorState");
       		if (ctorState != null  && !ctorState.isJsonNull() && !ctorState.getAsString().isEmpty()) {
       			connectorStatus = connectorState.get("connectorState").getAsString();       			
       		}
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Current connector state is: " + connectorStatus);
			if (sendToNotifier) {
				return connectorStatus;
			}			
		}catch(Exception e) {
			String error = " Exception while getting connector status. " + e.getMessage();			
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + error);
			logger.info(error);
			for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);			
		}
		List<String> newList = new ArrayList<String>(errorList);
		newList.addAll(successList);
		if (connectorStatus != null && newList.contains(connectorStatus)) {			
			return connectorStatus;
		} else {
			return null;
		}
	}// end of getScanFinishedStatus
   	
   	public JsonObject checkInstanceState(String ec2Id, String accountId) throws Exception {
   		JsonObject instanceDetails = new JsonObject();
   		try {
   			instanceDetails = apiClient.getInstanceState(ec2Id, accountId);
   			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Making POST Request: " + instanceDetails.get("request").getAsString());
   			if (instanceDetails.get("requestBody").getAsString() != null) buildLogger.println(new Timestamp(System.currentTimeMillis()) + " API POST request body: " + instanceDetails.get("requestBody").getAsString());   			
			buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Current instance state is: " + instanceDetails.get("instanceState").getAsString());			
			if (instanceDetails.has("apiError")) {
				throw new APIResponseException("API response: "+instanceDetails.get("apiError").getAsString() + ". Check EC2 details provided to launch the scan.");
			}
						
		}catch(Exception e) {	
			if (instanceDetails.has("apiError")) {
				throw e;
			} else {
				buildLogger.println(new Timestamp(System.currentTimeMillis()) + " Error getting instance state: " + e.getMessage());
			}
		}
   		if (instanceDetails.get("instanceState").getAsString().equalsIgnoreCase("RUNNING")) {
   			instanceDetails.addProperty("state", true);
   			return instanceDetails;		
   		} else {
   			instanceDetails.addProperty("state", false);
   			return instanceDetails;
   		}
   	}// end of checkInstanceState
} // end of PCScanEc2ConnectorLauncher class