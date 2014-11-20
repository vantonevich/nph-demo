package com.nextpathway.hadoop.keyserver.service;

import static org.junit.Assert.*;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URL;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class KeyDispenserServiceTest {

	KeyDispenserService service;
	
	@Before
	public void setUp() throws Exception {
		// i.e.
		// keytool -genkey -alias tester -dname "cn=tester,dc=nextpathway,dc=com" -keystore keyserver_keystore -keysize 2048 -validity 100000 -keyalg RSA
		URL resourceURL = KeyDispenserServiceImpl.class.getClassLoader().getResource("keyserver_keystore");
		String path = new File(resourceURL.toURI()).toString();
		service = new KeyDispenserServiceImpl(
				   /*store:*/path,
				/*keyAlias:*/"tester", 
			   /*storePass:*/"tester",
				 /*keyPass:*/"tester");
	}

	@After
	public void tearDown() throws Exception {
		service = null;
	}

	@Test
	public void testDecodePrivateKeyRequest() throws KeyDispenserException, UnsupportedEncodingException
	{
		byte[] enc = org.springframework.security.crypto.codec.Base64.encode("fred:fred".getBytes("UTF-8"));
		String s = new String(enc);
		System.out.println("===>>> hash == " + s);
		String request = service.getPrivateKeyRequest();
		String key = service.getPrivateKey(request);
		assertNotNull("Unable to decode private key request", key);
	}
}
