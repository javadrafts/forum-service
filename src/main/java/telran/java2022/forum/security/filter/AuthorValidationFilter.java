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

@Order(40)
@Component
public class AuthorValidationFilter implements Filter {
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		String method = httpRequest.getMethod();
		String servletPath = httpRequest.getServletPath();

		if (checkEndPoint(method, servletPath)) {
			String[] splittedServletPath = servletPath.split("/");

			String author = splittedServletPath[splittedServletPath.length - 1];

			if (!author.equals(httpRequest.getUserPrincipal().getName())) {
				httpResponse.sendError(403);
				return;
			}
		}

		chain.doFilter(httpRequest, httpResponse);
	}

	private boolean checkEndPoint(String method, String servletPath) {
		return (servletPath.matches("/forum/post/\\w+/?") && method.equalsIgnoreCase("post"))
				|| (servletPath.matches("/forum/post/\\w+/comment/\\w+/?") && method.equalsIgnoreCase("put"));
	}
}
