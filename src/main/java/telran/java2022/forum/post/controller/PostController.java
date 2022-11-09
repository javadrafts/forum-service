package telran.java2022.forum.post.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import telran.java2022.forum.post.dto.AddCommentDto;
import telran.java2022.forum.post.dto.AddPostDto;
import telran.java2022.forum.post.dto.PeriodDto;
import telran.java2022.forum.post.dto.PostDto;
import telran.java2022.forum.post.dto.UpdatePostDto;
import telran.java2022.forum.post.service.PostService;

@RestController
@RequiredArgsConstructor
public class PostController {
	final PostService postService;

	@PostMapping("forum/post/{author}")
	public PostDto addPost(@PathVariable String author, @RequestBody AddPostDto addPostDto) {
		return postService.addPost(author, addPostDto);
	}

	@GetMapping("forum/post/{id}")
	public PostDto findPostById(@PathVariable String id) {
		return postService.findPostById(id);
	}

	@PutMapping("forum/post/{postId}/like")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void addLike(@PathVariable String postId) {
		postService.addLike(postId);
	}

	@GetMapping("forum/posts/author/{author}")
	public List<PostDto> findPostsByAuthor(@PathVariable String author) {
		return postService.findPostsByAuthor(author);
	}

	@PutMapping("forum/post/{postId}/comment/{user}")
	public PostDto addComment(@PathVariable String postId, @PathVariable String user,
			@RequestBody AddCommentDto addCommentDto) {
		return postService.addComment(postId, user, addCommentDto);
	}

	@DeleteMapping("forum/post/{id}")
	public PostDto deletePost(@PathVariable String id) {
		return postService.deletePost(id);
	}

	@PostMapping("forum/posts/tags")
	public List<PostDto> findPostsByTags(@RequestBody String[] tags) {
		return postService.findPostsByTags(tags);
	}

	@PostMapping("forum/posts/period")
	public List<PostDto> findPostsByPeriod(@RequestBody PeriodDto periodDto) {
		return postService.findPostsByPeriod(periodDto);
	}

	@PutMapping("forum/post/{id}")
	public PostDto updatePost(@PathVariable String id, @RequestBody UpdatePostDto updatePostDto) {
		return postService.updatePost(id, updatePostDto);
	}
}
