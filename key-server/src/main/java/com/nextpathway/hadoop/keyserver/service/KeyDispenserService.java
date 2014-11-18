package com.nextpathway.hadoop.keyserver.service;


import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.text.ParseException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

interface KeyDispenserService {
	String getPrivateKey(String privateKeyRequest) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
				IllegalBlockSizeException, BadPaddingException, IOException, InvalidPrivateKeyRequestException,
				SignatureException, ParseException;

	String getPrivateKeyRequest() 
			throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException,
				SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException;
}
