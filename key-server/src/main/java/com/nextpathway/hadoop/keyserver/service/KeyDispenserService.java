package com.nextpathway.hadoop.keyserver.service;


interface KeyDispenserService {
	/** Reports private key as per submitted request.*/
	String getPrivateKey(String privateKeyRequest) throws KeyDispenserException;

	/** Generates private key request.*/
	String getPrivateKeyRequest() throws KeyDispenserException;
}
