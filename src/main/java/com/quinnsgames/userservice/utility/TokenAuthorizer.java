package com.quinnsgames.userservice.utility;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpStatus.FORBIDDEN;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class TokenAuthorizer {
	//This function ensures that the given access token is authentic.
	public static boolean authorizeToken(HttpServletResponse response, String authorizationHeader)
			throws ServletException, IOException {
		try {
			String token = authorizationHeader.substring("Bearer ".length());
			Algorithm algorithm = Algorithm.HMAC256(System.getenv("SecretString").getBytes());
			JWTVerifier verifier = JWT.require(algorithm).build();
			DecodedJWT decodedJWT = verifier.verify(token);
			String username = decodedJWT.getSubject();
			String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
			Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
			stream(roles).forEach(role -> {
				authorities.add(new SimpleGrantedAuthority(role));
			});
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(username, null, authorities);
			SecurityContextHolder.getContext().setAuthentication(authenticationToken);
			return true;
		}catch(Exception exception){
			log.error("Error logging in: {}", exception.getMessage());
			response.setHeader("error", exception.getMessage());
			response.setStatus(FORBIDDEN.value());
			
			Map<String, String> error = new HashMap<>();
			error.put("error_message", exception.getMessage());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			new ObjectMapper().writeValue(response.getOutputStream(), error);
			return false;
		}
	}
	
	//This looks scary, but all it does is decode the JWT and compare the encoded user to a given username.
	//Useful for restricting data to only certain users.
	public static boolean authorizeUser(HttpServletResponse response, String authorizationHeader, String username)
			throws ServletException, IOException {
		boolean success = authorizeToken(response, authorizationHeader);
		if(!success) {
			return false;
		}
		String token = authorizationHeader.substring("Bearer ".length());
		String[] chunks = token.split("\\.");
		Base64.Decoder decoder = Base64.getUrlDecoder();
		byte[] decoded = decoder.decode(chunks[1]);
		
		JSONObject obj = new JSONObject(new String(decoded));
		
		
		String authorizedUserName = obj.getString("sub");
		if(!authorizedUserName.equals(username)) {
			return false;
		}
		
		return true;
		
	}
}
