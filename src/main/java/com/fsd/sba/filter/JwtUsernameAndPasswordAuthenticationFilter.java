package com.fsd.sba.filter;

import java.io.IOException;
import java.sql.Date;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fsd.sba.config.JwtConfig;
import com.fsd.sba.model.UserCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter   {
	private static Logger logger = LoggerFactory.getLogger(JwtUsernameAndPasswordAuthenticationFilter.class);
	// We use auth manager to validate the user credentials
	private AuthenticationManager authManager;
	
	private final JwtConfig jwtConfig;
	
//	@Autowired
//	private AccountServiceClient accountclient;
    
	public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authManager, JwtConfig jwtConfig) {
		this.authManager = authManager;
		this.jwtConfig = jwtConfig;
		
		// By default, UsernamePasswordAuthenticationFilter listens to "/login" path. 
		// In our case, we use "/auth". So, we need to override the defaults.
		this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(jwtConfig.getUri(), "POST"));
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		try {
			UserCredentials creds = new UserCredentials();
			String userName = request.getParameter("userName");
			String password = request.getParameter("password");
			creds.setUsername(userName);
			creds.setPassword(password);
			logger.debug("user name is {}, password is {}", userName, password);
			
			// 2. Create auth object (contains credentials) which will be used by auth manager
			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
					creds.getUsername(), creds.getPassword(), Collections.emptyList());
			setDetails(request, authToken);
			// 3. Authentication manager authenticate the user, and use UserDetialsServiceImpl::loadUserByUsername() method to load the user.
			return authManager.authenticate(authToken);
			
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	// Upon successful authentication, generate a token.
	// The 'auth' passed to successfulAuthentication() is the current authenticated user.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication auth) throws IOException, ServletException {
		
		Long now = System.currentTimeMillis();
		String username = auth.getName();
		List<String> roles = auth.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority).collect(Collectors.toList());
		String token = Jwts.builder()
				.setSubject(username)
				// Convert to list of strings.
				// This is important because it affects the way we get them back in the Gateway.
			.claim("authorities", roles)
			.setIssuedAt(new Date(now))
			.setExpiration(new Date(now + jwtConfig.getExpiration() * 1000))  // in milliseconds
			.signWith(SignatureAlgorithm.HS512, jwtConfig.getSecret().getBytes())
			.compact();
		
		// Add token to header
//		response.addHeader(jwtConfig.getHeader(), jwtConfig.getPrefix() + token);
		response.setContentType("application/json");
	    response.setCharacterEncoding("UTF-8");
	    JsonObject json = new JsonObject();
	    json.addProperty("token", token);
	    json.addProperty("username", username);
	    json.addProperty("role", roles.get(0).split("_")[1]);
	    response.getWriter().write(json.toString());
	}

	
}

