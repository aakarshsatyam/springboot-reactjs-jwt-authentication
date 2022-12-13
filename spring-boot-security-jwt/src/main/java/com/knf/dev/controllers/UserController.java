package com.knf.dev.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.knf.dev.response.MessageResponse;

@CrossOrigin(origins = "*", maxAge = 4800)
@RestController
@RequestMapping("/api/test")
public class UserController {
	//allAccess is just simple method for testing
	@GetMapping("/all")
	public MessageResponse allAccess() {
		return new MessageResponse("Server is up.....");
	}
	//userAccess is just simple method for testing
	@GetMapping("/greeting")
	@PreAuthorize("isAuthenticated()")
	public MessageResponse userAccess() {

		return new MessageResponse("Congratulations! You are an authenticated user.");
	}

}
