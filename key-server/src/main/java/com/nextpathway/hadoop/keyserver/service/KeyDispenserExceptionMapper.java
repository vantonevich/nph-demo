package com.nextpathway.hadoop.keyserver.service;


import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyDispenserExceptionMapper implements ExceptionMapper<KeyDispenserException> {
	private static final Logger log = LoggerFactory.getLogger(KeyDispenserExceptionMapper.class);
	
	public Response toResponse(KeyDispenserException exception) {
		log.debug("Exception caught in key dispencer, reporting 406 (NOT_ACCEPTABLE) ", exception);
		return Response.status(Response.Status.NOT_ACCEPTABLE).build();
	}
}
