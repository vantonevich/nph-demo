package com.nextpathway.hadoop.keyserver.service;

public class InvalidPrivateKeyRequestException extends Exception {
	private static final long serialVersionUID = 3894368913340163241L;

	public InvalidPrivateKeyRequestException(String message) {
		super(message);
	}

}
