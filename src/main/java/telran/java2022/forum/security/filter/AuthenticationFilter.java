package telran.java2022.forum.security.filter;

import java.io.IOException;
import java.util.Base64;
import java.util.Optional;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.forum.user.dao.UserRepository;
import telran.java2022.forum.user.model.User;

@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements Filter {
	final UserRepository userRepository;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest)request;
		HttpServletResponse httpResponse = (HttpServletResponse)response;
		
		if (checkEndPoint(httpRequest.getMethod(), httpRequest.getServletPath())) {
			String token = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
			
			if (token == null) {
				httpResponse.sendError(401);
				return;
			}
			
			String[] credentials = getCredentialsFromToken(token);
			
			Optional<User> user = userRepository.findById(credentials[0]);
			
			if (user.isEmpty() || !user.get().getPassword().equals(credentials[1])) {
				httpResponse.sendError(401);
				return;
			}
		}
		
		chain.doFilter(request, response);
	}

	private String[] getCredentialsFromToken(String token) {
		return new String(Base64.getDecoder().decode(token.split(" ")[1])).split(":");
	}

	private boolean checkEndPoint(String method, String servletPath) {
		return !(method.equalsIgnoreCase("post") && servletPath.equals("/account/register"));
	}

}
