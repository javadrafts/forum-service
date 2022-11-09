package telran.java2022.forum.post.service;

import java.util.List;

import telran.java2022.forum.post.dto.AddCommentDto;
import telran.java2022.forum.post.dto.AddPostDto;
import telran.java2022.forum.post.dto.PeriodDto;
import telran.java2022.forum.post.dto.PostDto;
import telran.java2022.forum.post.dto.UpdatePostDto;

public interface PostService {
	PostDto addPost(String author, AddPostDto addPostDto);

	PostDto findPostById(String id);

	void addLike(String postId);

	List<PostDto> findPostsByAuthor(String author);

	PostDto addComment(String postId, String user, AddCommentDto addCommentDto);

	PostDto deletePost(String id);

	List<PostDto> findPostsByTags(String[] tags);

	List<PostDto> findPostsByPeriod(PeriodDto periodDto);

	PostDto updatePost(String id, UpdatePostDto updatePostDto);
}
