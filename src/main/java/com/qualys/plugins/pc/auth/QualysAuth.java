package com.qualys.plugins.pc.auth;

import java.util.ArrayList;
import java.util.List;

import hudson.util.Secret;

public class QualysAuth {
    private String server;
    private String username;
    private Secret password;
    private String authKey;
    private String proxyServer;
    private String proxyUsername;
    private boolean useProxy = false;
    private Secret proxyPassword;
    private int proxyPort;
    private String gatewayURL = null;
    public static List<String> serverPlatformURL = new ArrayList<String>();
    public static List<String> serverApiURL = new ArrayList<String>();
    public static List<String> serverGatewayURL = new ArrayList<String>();

    public QualysAuth () {
        
    }
    
    static {
    	serverPlatformURL.add("https://qualysguard.qualys.com");
    	serverPlatformURL.add("https://qualysguard.qg2.apps.qualys.com");
    	serverPlatformURL.add("https://qualysguard.qg3.apps.qualys.com");
    	serverPlatformURL.add("https://qualysguard.qg4.apps.qualys.com");
    	serverPlatformURL.add("https://qualysguard.qualys.eu");
    	serverPlatformURL.add("https://qualysguard.qg2.apps.qualys.eu");
    	serverPlatformURL.add("https://qualysguard.qg1.apps.qualys.in");
    	serverPlatformURL.add("https://qualysguard.qg1.apps.qualys.ca");
    	
    	serverApiURL.add("https://qualysapi.qualys.com");
    	serverApiURL.add("https://qualysapi.qg2.apps.qualys.com");
    	serverApiURL.add("https://qualysapi.qg3.apps.qualys.com");
    	serverApiURL.add("https://qualysapi.qg4.apps.qualys.com");
    	serverApiURL.add("https://qualysapi.qualys.eu");
    	serverApiURL.add("https://qualysapi.qg2.apps.qualys.eu");
    	serverApiURL.add("https://qualysapi.qg1.apps.qualys.in");
    	serverApiURL.add("https://qualysapi.qg1.apps.qualys.ca");
    	
    	serverGatewayURL.add("https://gateway.qg1.apps.qualys.com");
    	serverGatewayURL.add("https://gateway.qg2.apps.qualys.com");
    	serverGatewayURL.add("https://gateway.qg3.apps.qualys.com");
    	serverGatewayURL.add("https://gateway.qg4.apps.qualys.com");
    	serverGatewayURL.add("https://gateway.qg1.apps.qualys.eu");
    	serverGatewayURL.add("https://gateway.qg2.apps.qualys.eu");
    	serverGatewayURL.add("https://gateway.qg1.apps.qualys.in");
    	serverGatewayURL.add("https://gateway.qg1.apps.qualys.ca");
    	
    }

	public void setServer(String server) {
		this.server = server;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setPassword(Secret password) {
		this.password = password;
	}

	public void setAuthKey(String authKey) {
		this.authKey = authKey;
	}

	public void setProxyServer(String proxyServer) {
		this.proxyServer = proxyServer;
	}

	public void setProxyUsername(String proxyUsername) {
		this.proxyUsername = proxyUsername;
	}

	public void setUseProxy(boolean useProxy) {
		this.useProxy = useProxy;
	}

	public void setProxyPassword(Secret proxyPassword) {
		this.proxyPassword = proxyPassword;
	}

	public void setProxyPort(int proxyPort) {
		this.proxyPort = proxyPort;
	}

	public String getServer() {
    	if (server == null) {
    		return "https://qualysapi.qualys.com";
    	}else {
    		return server.replace("qualysguard", "qualysapi");
    	}
    }
	
	public String getServerPlatformUrl() {
		int pos;
		if (gatewayURL == null) {
			if (server.endsWith("/")) {
				server = server.substring(0, server.length() - 1);
			}
			pos = serverPlatformURL.indexOf(server);
			if (pos == -1) {
				pos = serverApiURL.indexOf(server);
			}
			if (pos == -1) {
				pos = serverGatewayURL.indexOf(server);
			}
			if (pos == -1) {
				//gatewayURL = server.replace("https://qualysapi.", "https://qualysguard.");
				gatewayURL = server;
			} else {
				gatewayURL = serverPlatformURL.get(pos);
			}
		}

		return gatewayURL;
	}
	
	public String getServerForTestConnection() {
		int pos;
		if (gatewayURL == null) {
			if (server.endsWith("/")) {
				server = server.substring(0, server.length() - 1);
			}
			pos = serverPlatformURL.indexOf(server);
			if (pos == -1) {
				pos = serverApiURL.indexOf(server);
			}
			if (pos == -1) {
				pos = serverGatewayURL.indexOf(server);
			}
			if (pos == -1) {
				gatewayURL = server.replace("https://qualysapi.", "https://qualysgateway.");
			} else {
				gatewayURL = serverGatewayURL.get(pos);
			}
		}

		return gatewayURL;
	}

    public String getUsername() {
    	if (username == null) {
    		return "";
    	}else {
    		return username;
    	}
    }

    public Secret getPassword() {
    	if (password  == null) {
    		return Secret.fromString("");
    	}else {
    		return password;
    	}
    }
    
    public String getProxyServer() {
    	if (proxyServer == null) {
    		return "";
    	}else {
    		return proxyServer;
    	}
    }

    public String getProxyUsername() {        
        if (proxyUsername == null) {
    		return "";
    	}else {
    		return proxyUsername;
    	}
    }

    public Secret getProxyPassword() {
    	if (proxyPassword == null) {
    		return Secret.fromString("");
    	}else {
    		return proxyPassword;
    	}
    }
    public int getProxyPort() {    	
        return proxyPort;
    }
    public String getAuthKey() {
        return authKey;
    }
    public boolean getUseProxy() {
    	if (useProxy) {
    		return true;
    	}else {
    		return useProxy;
    	}
    }
   
    public void setQualysCredentials(String server, String username, String password) {
        this.server = server;
        this.username = username;
        this.password = Secret.fromString(password);
    }
	
	  public void setProxyCredentials(String proxyServer, int proxyPort, String
	  proxyUsername, String proxyPassword, boolean useProxy) { 
		  this.proxyServer = proxyServer;
		  this.proxyPort = proxyPort; 
		  this.useProxy = useProxy;
		  if(proxyUsername != null) {
			  this.proxyUsername = proxyUsername;
		  } else {
			  this.proxyUsername = null;
		  }
		  
		  if(proxyPassword != null) {
			  this.proxyPassword = Secret.fromString(proxyPassword);
		  } else {
			  this.proxyPassword = null;
		  }
	  }
}