package telran.java2022.forum.security.filter;

import java.io.IOException;
import java.security.Principal;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.forum.user.dao.UserRepository;
import telran.java2022.forum.user.model.User;

@Order(10)
@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements Filter {
	final UserRepository userRepository;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		String method = httpRequest.getMethod();
		String servletPath = httpRequest.getServletPath();

		if (checkEndPoint(method, servletPath)) {
			String token = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);

			if (token == null) {
				httpResponse.sendError(401);
				return;
			}

			String[] credentials;
			try {
				credentials = getCredentialsFromToken(token);
			} catch (Exception e) {
				httpResponse.sendError(400, "Invalid token.");
				return;
			}

			User user = userRepository.findById(credentials[0]).orElse(null);

			if (user == null || !BCrypt.checkpw(credentials[1], user.getPassword())) {
				httpResponse.sendError(401);
				return;
			}

			httpRequest = new WrappedRequest(httpRequest, user.getLogin());
		}

		chain.doFilter(httpRequest, httpResponse);
	}

	private String[] getCredentialsFromToken(String token) {
		return new String(Base64.getDecoder().decode(token.split(" ")[1])).split(":");
	}

	private boolean checkEndPoint(String method, String servletPath) {
		return !((method.equalsIgnoreCase("post") && servletPath.matches("/account/register/?"))
				|| servletPath.startsWith("/forum/posts/"));
	}

	private static class WrappedRequest extends HttpServletRequestWrapper {
		String login;

		public WrappedRequest(HttpServletRequest request, String login) {
			super(request);
			this.login = login;
		}

		@Override
		public Principal getUserPrincipal() {
			return () -> login;
		}
	}
}
