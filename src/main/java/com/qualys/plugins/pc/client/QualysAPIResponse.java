package com.qualys.plugins.pc.client;

class QualysAPIResponse {
    private int         responseCode = 0;
    private boolean     errored = false;
    private String      errorMessage = "";  

    /**
	 * @return the responseCode
	 */
	public int getResponseCode() {
		return responseCode;
	}

	/**
	 * @param responseCode the responseCode to set
	 */
	public void setResponseCode(int responseCode) {
		this.responseCode = responseCode;
	}

	/**
	 * @return the errored
	 */
	public boolean isErrored() {
		return errored;
	}

	/**
	 * @param errored the errored to set
	 */
	public void setErrored(boolean errored) {
		this.errored = errored;
	}

	/**
	 * @return the errorMessage
	 */
	public String getErrorMessage() {
		return errorMessage;
	}

	/**
	 * @param errorMessage the errorMessage to set
	 */
	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}
}