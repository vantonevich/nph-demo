package com.nextpathway.hadoop.keyserver.service;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

interface KeyDispenserServiceSite {
	KeyPair getKeyPair() throws NoSuchAlgorithmException;
}