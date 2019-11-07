package com.fsd.sba.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.fsd.sba.client.AccountServiceClient;
import com.fsd.sba.model.User;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

@Service // It has to be annotated with @Service.
public class UserDetailsServiceImpl implements UserDetailsService {
	private static final Logger logger = LoggerFactory.getLogger(UserDetailsService.class);
	@Autowired
	private AccountServiceClient accountclient;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		try {
			ResponseEntity<Object> result = accountclient.getUser(username);
			JsonObject accountresult = getResult(result);

			if (accountresult.get("code").getAsInt() == 404) {
				throw new UsernameNotFoundException("用户 " + username + " 不存在");
			} else {
				User user = getAccount(accountresult);
				List<GrantedAuthority> grantedAuthorities = AuthorityUtils
	                	.commaSeparatedStringToAuthorityList("ROLE_"+user.getRole());
				logger.error("user password is: {}", user.getPassword());
				return new org.springframework.security.core.userdetails.User(user.getUserName(), user.getPassword(), grantedAuthorities);
			}

		} catch (Exception ex) {
			throw new UsernameNotFoundException(ex.getMessage());
		}

	}

	public JsonObject getResult(ResponseEntity<Object> result) {
		Gson gson = new Gson();
		String jsonResultStr = gson.toJson(result.getBody());
		JsonParser parser = new JsonParser();
		JsonObject object = (JsonObject) parser.parse(jsonResultStr);
		return object;

	}

	public User getAccount(JsonObject result) {
		Gson gson = new Gson();
		User user = gson.fromJson(result.get("data").toString(), User.class);
		return user;

	}
}
