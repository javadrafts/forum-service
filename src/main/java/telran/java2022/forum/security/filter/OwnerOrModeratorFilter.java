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
import telran.java2022.forum.post.dao.PostRepository;
import telran.java2022.forum.post.model.Post;
import telran.java2022.forum.security.context.SecurityContext;
import telran.java2022.forum.security.context.UserIdentity;
import telran.java2022.forum.user.dao.UserRepository;
import telran.java2022.forum.user.model.User;

@Order(30)
@Component
@RequiredArgsConstructor
public class OwnerOrModeratorFilter implements Filter {
	final SecurityContext securityContext;
	final PostRepository postRepository;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		String method = httpRequest.getMethod();
		String servletPath = httpRequest.getServletPath();

		if (checkEndPoint(method, servletPath)) {
			UserIdentity userIdentity = securityContext.getUser(httpRequest.getUserPrincipal().getName());

			boolean moderatorAccessEnforced = userIdentity.getRoles().contains("MODERATOR")
					&& checkModeratorAccess(method, servletPath);

			if (!moderatorAccessEnforced) {
				if (checkOwnerAccess(method, servletPath)) {
					String[] splittedServletPath = servletPath.split("/");

					String postId = splittedServletPath[splittedServletPath.length - 1];

					Post post = postRepository.findById(postId).orElse(null);

					if (post == null) {
						httpResponse.sendError(404);
						return;
					}

					if (!post.getAuthor().equals(userIdentity.getUserName())) {
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
		return servletPath.matches("/forum/post/\\w+/?")
				&& (method.equalsIgnoreCase("delete") || method.equalsIgnoreCase("put"));
	}

	private boolean checkModeratorAccess(String method, String servletPath) {
		return method.equalsIgnoreCase("delete");
	}

	private boolean checkOwnerAccess(String method, String servletPath) {
		return true;
	}
}
