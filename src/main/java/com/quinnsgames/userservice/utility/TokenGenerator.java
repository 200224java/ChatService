package com.quinnsgames.userservice.utility;

import java.util.Date;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.quinnsgames.userservice.domain.Role;
import com.quinnsgames.userservice.domain.User;

public class TokenGenerator {
	//Whip up a fresh access token.
	public static String generateAccessToken(HttpServletRequest request, User user) {
		Algorithm algorithm = getAlgorithm();
		return JWT.create()
				.withSubject(user.getUsername()) //The subject is the user's username. This is useful for making sure you have the right person.
				.withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000 * 100000)) //I set them to expire only after a really long time, just for ease of testing.
				.withIssuer(request.getRequestURL().toString())
				.withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
				.sign(algorithm);
	}
	
	//public static
	
	public static Algorithm getAlgorithm() {
		return Algorithm.HMAC256(System.getenv("SecretString").getBytes()); //Sign it with a secret string stored in the environment.
	}
}
