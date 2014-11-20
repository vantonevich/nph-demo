package com.nextpathway.hadoop.keyserver.service;


import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

import org.springframework.security.access.AccessDeniedException;

public class AccessDeniedExceptionMapper implements ExceptionMapper<AccessDeniedException> {
	public Response toResponse(AccessDeniedException exception) {
		return Response.status(Response.Status.FORBIDDEN).build();
	}
}
