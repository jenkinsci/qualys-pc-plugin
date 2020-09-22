package com.qualys.plugins.pc.client;

import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;

import com.qualys.plugins.pc.auth.QualysAuth;

class QualysBaseClient {
    private QualysAuth auth;
    protected PrintStream stream;
    protected int timeout = 30; // in seconds

    public QualysBaseClient (QualysAuth auth) {
        this.auth = auth;
        this.stream = System.out;
    }

    public QualysBaseClient(QualysAuth auth, PrintStream stream) {
        this.auth = auth;
        this.stream = stream;
    }

    public URL getAbsoluteUrl(String path) throws MalformedURLException {
        path = (path.startsWith("/")) ? path : ("/" + path);
        URL url = new URL(this.auth.getServer() + path);
        return url;
    }
    
    public URL getAbsoluteUrlForTestConnection(String path) throws MalformedURLException {
        path = (path.startsWith("/")) ? path : ("/" + path);
        URL url = new URL(this.auth.getServerForTestConnection() + path);
        return url;
    }
    
    protected byte[] getJWTAuthHeader() throws UnsupportedEncodingException {
        String userPass = "username=" + java.net.URLEncoder.encode(this.auth.getUsername(), "UTF-8")  + "&password=" + java.net.URLEncoder.encode(this.auth.getPassword().getPlainText(), "UTF-8") + "&token=true";
        return userPass.getBytes();
    }
    // This class is used to prepare the credentials by encrypting them for Https request call.
    // This is used in QualysCSClient for [GET] or [POST] calls
    protected String getBasicAuthHeader() {
        String userPass = this.auth.getUsername() + ":" + this.auth.getPassword().getPlainText();
        String encoded = Base64.getEncoder().encodeToString((userPass).getBytes(StandardCharsets.UTF_8));
        return encoded;
    }
    
    protected CloseableHttpClient getHttpClient() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
    	RequestConfig config = RequestConfig.custom()
  	    	  .setConnectTimeout(this.timeout * 10000)
  	    	  .setConnectionRequestTimeout(this.timeout * 10000)
  	    	  .setSocketTimeout(this.timeout * 10000).build(); // Timeout settings
    	SSLContextBuilder builder = new SSLContextBuilder();
    	SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build());
    	final HttpClientBuilder clientBuilder = HttpClients.custom().setSSLSocketFactory(sslsf);
    	
    	final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
    	
    	clientBuilder.setDefaultRequestConfig(config);
    	clientBuilder.setDefaultCredentialsProvider(credentialsProvider);    	
    	
    	if(this.auth.getProxyServer() != null && !this.auth.getProxyServer().isEmpty()) { 
    		final HttpHost proxyHost = new HttpHost(this.auth.getProxyServer(),this.auth.getProxyPort()); 	
    		final HttpRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxyHost);
    		clientBuilder.setRoutePlanner(routePlanner);
    		
    		String proxUsername = this.auth.getProxyUsername();
    		String proxPassword = this.auth.getProxyPassword().getPlainText();
            
            if (proxUsername != null && !proxUsername.trim().isEmpty()) {
                System.out.println("Using proxy authentication (user=" + proxUsername + ") & its password.");
                credentialsProvider.setCredentials(new AuthScope(proxyHost), 
                								   new UsernamePasswordCredentials(proxUsername, proxPassword));
            }    		
    	}
    	return clientBuilder.build();
    } 
    
    /**
     * This method use to set connection timeout for http client.   
     * @param timeout - int - in secs
     */
    public void setTimeout(int timeout) {
    	this.timeout = timeout;    	
    }
}
