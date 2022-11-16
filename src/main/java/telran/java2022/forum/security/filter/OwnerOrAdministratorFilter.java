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
import telran.java2022.forum.security.context.SecurityContext;
import telran.java2022.forum.security.context.UserIdentity;

@Order(20)
@Component
@RequiredArgsConstructor
public class OwnerOrAdministratorFilter implements Filter {
	final SecurityContext securityContext;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		String method = httpRequest.getMethod();
		String servletPath = httpRequest.getServletPath();

		if (checkEndPoint(method, servletPath)) {
			UserIdentity userIdentity = securityContext.getUser(httpRequest.getUserPrincipal().getName());

			boolean administratorAccessEnforced = userIdentity.getRoles().contains("ADMINISTRATOR")
					&& checkAdministratorAccess(method, servletPath);

			if (!administratorAccessEnforced) {
				if (checkOwnerAccess(method, servletPath)) {
					String[] splittedServletPath = servletPath.split("/");

					String login = splittedServletPath[splittedServletPath.length - 1];

					if (!login.equals(userIdentity.getUserName())) {
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
