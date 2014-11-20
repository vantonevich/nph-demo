package com.nextpathway.hadoop.keyserver.service;

public class KeyDispenserException extends Exception {
	private static final long serialVersionUID = 3894368913340163241L;

	public KeyDispenserException(String message) {
		super(message);
	}

	public KeyDispenserException(String message, Throwable cause) {
		super(message, cause);
	}
}