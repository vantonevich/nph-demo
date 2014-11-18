package com.nextpathway.hadoop.keyserver.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;

@Path("/service")
public class KeyDispenserServiceImpl implements KeyDispenserService {

	private KeyPair cachedKeyPair = null;
	private final KeyDispenserServiceSite site;
	
	private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssz'!'");

	@Inject
	public KeyDispenserServiceImpl(KeyDispenserServiceSite site) {
		this.site = site;
	}

	@GET
	@Path("/private")
	public String getPrivateKey(@PathParam("r") String privateKeyRequest) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, IOException, InvalidPrivateKeyRequestException,
			SignatureException, ParseException 
	{
		// decode encrypted bytes
		Base64.Decoder decoder = Base64.getDecoder();
		byte encryptedMessageBytes[] = decoder.decode(privateKeyRequest);

		// Decrypt message
		int chunkSize = 256;
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		KeyPair keyPair = getKeyPair();
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		ByteArrayOutputStream decryptedByteStream = new ByteArrayOutputStream();
		for (int begin = 0; begin < encryptedMessageBytes.length; begin += chunkSize) {
			byte[] decryptedChunk = cipher.doFinal(encryptedMessageBytes, begin, chunkSize);
			decryptedByteStream.write(decryptedChunk);
		}
		byte[] messageBytes = decryptedByteStream.toByteArray();
		String message = new String(messageBytes, "UTF8");

		// Split message
		int pos = message.indexOf('!');
		if (pos < 0) {
			throw new InvalidPrivateKeyRequestException("Invalid format: no separator");
		}
		if (pos + 1 == message.length()) {
			throw new InvalidPrivateKeyRequestException("Invalid format: no signature");
		}
		String signature = message.substring(pos + 1);
		String requestData = message.substring(0, pos + 1);
		
		// validate signature
		byte[] requestDataBytes = requestData.getBytes("UTF8");
		byte[] signatureBytes = decoder.decode(signature);
		Signature sig = Signature.getInstance("SHA1WithRSA");
		sig.initVerify(keyPair.getPublic());
		sig.update(requestDataBytes);
		boolean verified = sig.verify(signatureBytes);
		if (!verified) {
			throw new InvalidPrivateKeyRequestException("Invalid signature");
		}
		
		// validate expiry
		Date requestDate = dateFormat.parse(requestData);
		Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		c.add(Calendar.SECOND, -3600);
		Date cutoffDate = c.getTime();
		if (requestDate.compareTo(cutoffDate) < 0) {
			throw new InvalidPrivateKeyRequestException("Expired request");
		}
		
		// report key
		PrivateKey privateKey = keyPair.getPrivate();
		byte[] keyBytes = privateKey.getEncoded();
		Base64.Encoder encoder = Base64.getEncoder();
		String privateKeyData = encoder.encodeToString(keyBytes);

		return privateKeyData;
	}

	@GET
	@Path("/public")
	public String getPrivateKeyRequest() 
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException
	{
		Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		Date tm = c.getTime();
		String requestData = dateFormat.format(tm);
		byte[] requestDataBytes = requestData.getBytes("UTF8");

		// Sign the data
		Signature sig = Signature.getInstance("SHA1WithRSA");
		KeyPair keyPair = getKeyPair();
		sig.initSign(keyPair.getPrivate());
		sig.update(requestDataBytes);
		byte[] signatureBytes = sig.sign();
		Base64.Encoder encoder = Base64.getEncoder();
		String signature = encoder.encodeToString(signatureBytes);

		// Concatenate signature
		StringBuilder b = new StringBuilder(requestData);
		b.append(signature);
		String message = b.toString();

		// Encrypt and return
		byte[] messageBytes = message.getBytes("UTF8");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		int blockSize = 245;
		ByteArrayOutputStream encryptedByteStream = new ByteArrayOutputStream();
		int begin = 0;
		while (begin < messageBytes.length) {
			int len;
			byte[] encryptedChunk;
			if (begin + blockSize >= messageBytes.length) {
				len = messageBytes.length - begin;
			} else {
				len = blockSize;
			}
			encryptedChunk = cipher.doFinal(messageBytes, begin, len);
			encryptedByteStream.write(encryptedChunk);
			begin += blockSize;
		}

		byte encryptedMessageBytes[] = encryptedByteStream.toByteArray();
		String privateKeyRequest = encoder.encodeToString(encryptedMessageBytes);
		return privateKeyRequest;
	}

	private synchronized KeyPair getKeyPair() throws NoSuchAlgorithmException {
		if (cachedKeyPair == null) {
			cachedKeyPair = site.getKeyPair();
		}
		return cachedKeyPair;
	}
}