package com.example.hw4.controllers;

import com.example.hw4.configs.jwt.JwtUtils;
import com.example.hw4.models.ERole;
import com.example.hw4.models.Role;
import com.example.hw4.models.User;
import com.example.hw4.pojo.JwtResponse;
import com.example.hw4.pojo.LoginRequest;
import com.example.hw4.pojo.MessageResponse;
import com.example.hw4.pojo.SignupRequest;
import com.example.hw4.repository.RoleRepository;
import com.example.hw4.repository.UserRepository;
import com.example.hw4.service.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRespository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	JwtUtils jwtUtils;

	@PostMapping("/signin")
	public ResponseEntity<?> authUser(@RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(
						loginRequest.getUsername(),
						loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		List<String> roles = userDetails.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());

		return ResponseEntity.ok(new JwtResponse(jwt,
				userDetails.getId(),
				userDetails.getUsername(),
				userDetails.getEmail(),
				roles));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest) {

		if (userRespository.existsByUsername(signupRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Username already exists"));
		}

		if (userRespository.existsByEmail(signupRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Email already exists"));
		}

		User user = new User(signupRequest.getUsername(),
				signupRequest.getEmail(),
				passwordEncoder.encode(signupRequest.getPassword()));

		Set<String> reqRoles = signupRequest.getRoles();
		Set<Role> roles = new HashSet<>();

		if (reqRoles == null) {
			Role userRole = roleRepository
					.findByName(ERole.ROLE_CUSTOMER)
					.orElseThrow(() -> new RuntimeException("Role CUSTOMER not found"));
			roles.add(userRole);
		} else {
			reqRoles.forEach(r -> {
				switch (r) {
					case "manager" -> {
						Role adminRole = roleRepository
								.findByName(ERole.ROLE_MANAGER)
								.orElseThrow(() -> new RuntimeException("Role MANAGER not found"));
						roles.add(adminRole);
					}
					case "chef" -> {
						Role modRole = roleRepository
								.findByName(ERole.ROLE_CHEF)
								.orElseThrow(() -> new RuntimeException("Role CHEF is not found"));
						roles.add(modRole);
					}
					default -> {
						Role userRole = roleRepository
								.findByName(ERole.ROLE_CUSTOMER)
								.orElseThrow(() -> new RuntimeException("Error, Role CUSTOMER is not found"));
						roles.add(userRole);
					}
				}
			});
		}
		user.setRoles(roles);
		userRespository.save(user);
		return ResponseEntity.ok(new MessageResponse("User CREATED"));
	}
}
