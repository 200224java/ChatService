package com.quinnsgames.userservice.api;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.quinnsgames.userservice.domain.Role;
import com.quinnsgames.userservice.domain.User;
import com.quinnsgames.userservice.service.UserService;
import com.quinnsgames.userservice.utility.TokenAuthorizer;
import com.quinnsgames.userservice.utility.TokenGenerator;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

//This is the resource which exposes all of the endpoints necessary for adding and retrieving users.
@RestController 
@RequestMapping("/api") 
@RequiredArgsConstructor
@Slf4j
public class UserResource {
	private final UserService userService;
	
	//Retrieve every user.
	@CrossOrigin
	@GetMapping(path="/users")
	public ResponseEntity<List<User>> getUsers(){
		return ResponseEntity.ok().body(userService.getUsers());
	}
	
	//Retrieve the user going by the given username, passed in the path.
	@CrossOrigin
	@GetMapping(path="/user/{username}")
	public ResponseEntity<User> getUserByUsername(@PathVariable String username){
		User user = userService.getUser(username);
		
		if(user == null) {
			return ResponseEntity.notFound().build();
		}
		user.setPassword("");
		return ResponseEntity.ok(user);
	}
	
	//Save a user to the database, as long as no one already has that name. They will automatically get the ROLE_USER role.
	//This is used in signing up.
	@CrossOrigin
	@PostMapping(path="/user/save")
	public ResponseEntity<User> saveUser(@RequestBody User user){
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
		User conflictingUser = userService.getUser(user.getUsername());
		if(conflictingUser != null) {
			log.error("Already a user by the name " + user.getUsername());
			return ResponseEntity.badRequest().body(user);
		}
		
		User endUser = userService.saveUser(user);
		userService.addRoleToUser(user.getUsername(), "ROLE_USER");
		
		return ResponseEntity.created(uri).body(endUser);
	}
	
	//Add a role to the database. Not used.
	@CrossOrigin
	@PostMapping(path="/role/save")
	public ResponseEntity<Role> saveRole(@RequestBody Role role){
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveRole(role));
	}
	
	//Add a role to the user. Another vestige of the tutorial that would be useful in larger projects.
	@CrossOrigin
	@PostMapping(path="/role/addtouser")
	public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form){
		userService.addRoleToUser(form.getUsername(), form.getRoleName());
		return ResponseEntity.ok().build();
	}
	
	//Update a user's information by passing in an updated user.
	@CrossOrigin
	@PutMapping(path="/user/update")
	public ResponseEntity<String> updateUser(HttpServletRequest request, HttpServletResponse response, @RequestBody User user, @RequestBody User updatedUser) throws ServletException, IOException{
		if(!TokenAuthorizer.authorizeUser(response, request.getHeader(AUTHORIZATION), user.getUsername())) {
			return ResponseEntity.status(FORBIDDEN).body("Unauthorized user update.");
		}
		
		return ResponseEntity.ok().body("User updated successfully.");
	}
}

@Data
class RoleToUserForm{
	private String username;
	private String roleName;
}
