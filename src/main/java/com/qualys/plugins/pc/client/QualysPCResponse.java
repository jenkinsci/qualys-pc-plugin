package com.qualys.plugins.pc.client;

import org.w3c.dom.Document;
import com.google.gson.JsonObject;

public class QualysPCResponse extends QualysAPIResponse{
    private JsonObject response = null;
    private Document responseXml = null;
    private String request = null;
    private String requestBody = null;
    private String requestParam = null;

	/**
	 * @return the response
	 */
	public JsonObject getResponse() {
		return response;
	}

	/**
	 * @param response the response to set
	 */
	public void setResponse(JsonObject response) {
		this.response = response;
	}

	/**
	 * @return the responseXml
	 */
	public Document getResponseXml() {
		return responseXml;
	}

	/**
	 * @param responseXml the responseXml to set
	 */
	public void setResponseXml(Document responseXml) {
		this.responseXml = responseXml;
	}

	/**
	 * @return the request
	 */
	public String getRequest() {
		return request;
	}

	/**
	 * @param request the request to set
	 */
	public void setRequest(String request) {
		this.request = request;
	}

	/**
	 * @return the requestBody
	 */
	public String getRequestBody() {
		return requestBody;
	}

	/**
	 * @param requestBody the requestBody to set
	 */
	public void setRequestBody(String requestBody) {
		this.requestBody = requestBody;
	}

	/**
	 * @return the requestParam
	 */
	public String getRequestParam() {
		return requestParam;
	}

	/**
	 * @param requestParam the requestParam to set
	 */
	public void setRequestParam(String requestParam) {
		this.requestParam = requestParam;
	}
}