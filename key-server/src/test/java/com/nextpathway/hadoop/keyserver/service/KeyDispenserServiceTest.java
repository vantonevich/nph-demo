package com.nextpathway.hadoop.keyserver.service;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.text.ParseException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class KeyDispenserServiceTest implements KeyDispenserServiceSite {

	KeyDispenserService service;
	
	@Before
	public void setUp() throws Exception {
		service = new KeyDispenserServiceImpl(this);
	}

	@After
	public void tearDown() throws Exception {
		service = null;
	}

	@Test
	public void testDecodePrivateKeyRequest() 
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchPaddingException, 
				IllegalBlockSizeException, BadPaddingException, IOException, InvalidPrivateKeyRequestException, 
				ParseException
	{
		String request = service.getPrivateKeyRequest();
		String key = service.getPrivateKey(request);
		assertNotNull("Unable to decode private key request", key);
	}

	@Override
	public KeyPair getKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		return kpg.genKeyPair();
	}
}
