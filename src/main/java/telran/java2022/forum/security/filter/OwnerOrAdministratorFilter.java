package telran.java2022.forum.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.forum.user.dao.UserRepository;
import telran.java2022.forum.user.model.User;

@Order(20)
@Component
@RequiredArgsConstructor
public class OwnerOrAdministratorFilter implements Filter {
	final UserRepository userRepository;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		String method = httpRequest.getMethod();
		String servletPath = httpRequest.getServletPath();

		if (checkEndPoint(method, servletPath)) {
			User user = userRepository.findById(httpRequest.getUserPrincipal().getName()).get();

			boolean administratorAccessEnforced = user.getRoles().contains("ADMINISTRATOR")
					&& checkAdministratorAccess(method, servletPath);

			if (!administratorAccessEnforced) {
				if (checkOwnerAccess(method, servletPath)) {
					String[] splittedServletPath = servletPath.split("/");

					String login = splittedServletPath[splittedServletPath.length - 1];

					if (!login.equals(user.getLogin())) {
						httpResponse.sendError(403);
						return;
					}
				} else {
					httpResponse.sendError(403);
					return;
				}
			}
		}

		chain.doFilter(httpRequest, httpResponse);
	}

	private boolean checkEndPoint(String method, String servletPath) {
		return servletPath.startsWith("/account/user/");
	}

	private boolean checkAdministratorAccess(String method, String servletPath) {
		return servletPath.matches("/account/user/\\w+/role/\\w+/?") || method.equalsIgnoreCase("delete");
	}

	private boolean checkOwnerAccess(String method, String servletPath) {
		return servletPath.matches("/account/user/\\w+/?");
	}
}
