package com.nextpathway.hadoop.keyserver.service;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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
	private final String keystorePath;
	private final char[] storePassword;
	private final char[] keyPassword;
	private final String keyAlias;
	
	private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssz'!'");

	@Inject
	public KeyDispenserServiceImpl(String keystorePath, String keyAlias, String storePassword, String keyPassword) {
		this.keystorePath = keystorePath;
		this.storePassword= storePassword.toCharArray();
		this.keyPassword= keyPassword.toCharArray();
		this.keyAlias = keyAlias;
	}

	@GET
	@Path("/acquire/{r}")
	public String getPrivateKey(@PathParam("r") String privateKeyRequest) throws KeyDispenserException
	{
		try {
			// decode encrypted bytes
			Base64.Decoder urlDecoder = Base64.getUrlDecoder();
			byte encryptedMessageBytes[] = urlDecoder.decode(privateKeyRequest);

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
				throw new KeyDispenserException("Invalid format: no separator");
			}
			if (pos + 1 == message.length()) {
				throw new KeyDispenserException("Invalid format: no signature");
			}
			String signature = message.substring(pos + 1);
			String requestData = message.substring(0, pos + 1);

			// validate signature
			byte[] requestDataBytes = requestData.getBytes("UTF8");
			Base64.Decoder decoder = Base64.getDecoder();
			byte[] signatureBytes = decoder.decode(signature);
			Signature sig = Signature.getInstance("SHA1WithRSA");
			sig.initVerify(keyPair.getPublic());
			sig.update(requestDataBytes);
			boolean verified = sig.verify(signatureBytes);
			if (!verified) {
				throw new KeyDispenserException("Invalid signature");
			}

			// validate expiry
			Date requestDate = dateFormat.parse(requestData);
			Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
			c.add(Calendar.SECOND, -3600);
			Date cutoffDate = c.getTime();
			if (requestDate.compareTo(cutoffDate) < 0) {
				throw new KeyDispenserException("Expired request");
			}

			// report key
			PrivateKey privateKey = keyPair.getPrivate();
			byte[] keyBytes = privateKey.getEncoded();
			Base64.Encoder encoder = Base64.getEncoder();
			String privateKeyData = encoder.encodeToString(keyBytes);

			return privateKeyData;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
				IllegalBlockSizeException | BadPaddingException | IOException |
				SignatureException | ParseException | NullPointerException | IllegalArgumentException e ) {
			throw new KeyDispenserException("Private key retrieval aborted", e);
		}
	}

	@GET
	@Path("/init")
	public String getPrivateKeyRequest() throws KeyDispenserException
	{
		try {
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
			Base64.Encoder urlEncoder = Base64.getUrlEncoder();
			String privateKeyRequest = urlEncoder.encodeToString(encryptedMessageBytes);
			return privateKeyRequest;
		} catch (NoSuchAlgorithmException | InvalidKeyException |
				SignatureException | NoSuchPaddingException | IllegalBlockSizeException |
				BadPaddingException | IOException e) {
			throw new KeyDispenserException("Private key request aborted", e);
		}
	}

	private synchronized KeyPair getKeyPair() throws KeyDispenserException  
	{
		if (cachedKeyPair == null) {
			try {
				String keyStoreType = KeyStore.getDefaultType();
				KeyStore keyStore = KeyStore.getInstance(keyStoreType);
				try (FileInputStream  in = new FileInputStream(keystorePath)) {
					try (BufferedInputStream inputStream = new BufferedInputStream(in)) {
						keyStore.load(inputStream, storePassword);
					}
				}
				Key key = keyStore.getKey(keyAlias, keyPassword);
				if (!(key instanceof PrivateKey)) {
					throw new KeyDispenserException("Key store does not contain private key with alias " + keyAlias);
				}
				// Get certificate of public key
				Certificate cert = keyStore.getCertificate(keyAlias);
	
				// Get public key
				PublicKey publicKey = cert.getPublicKey();
	
				// Return a key pair
				cachedKeyPair = new KeyPair(publicKey, (PrivateKey) key);
			} catch (KeyStoreException | NoSuchAlgorithmException | IOException |
					CertificateException  | UnrecoverableKeyException e) {
				throw new KeyDispenserException("Key load aborted, keyAlias= " + keyAlias, e);
			}
		}
		return cachedKeyPair;
	}
}