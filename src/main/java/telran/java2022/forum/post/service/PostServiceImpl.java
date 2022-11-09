package telran.java2022.forum.post.service;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.stream.Stream;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java2022.forum.post.dao.PostRepository;
import telran.java2022.forum.post.dto.AddCommentDto;
import telran.java2022.forum.post.dto.AddPostDto;
import telran.java2022.forum.post.dto.PeriodDto;
import telran.java2022.forum.post.dto.PostDto;
import telran.java2022.forum.post.dto.exceptions.PostNotFoundException;
import telran.java2022.forum.post.model.Post;
import telran.java2022.forum.post.model.Post.Comment;
import telran.java2022.forum.post.dto.UpdatePostDto;

@Service
@RequiredArgsConstructor
public class PostServiceImpl implements PostService {
	final PostRepository postRepository;
	final ModelMapper modelMapper;

	@Override
	public PostDto addPost(String author, AddPostDto addPostDto) {
		Post post = modelMapper.map(addPostDto, Post.class);

		post.setAuthor(author);

		post = postRepository.save(post);

		return modelMapper.map(post, PostDto.class);
	}

	@Override
	public PostDto findPostById(String id) {
		Post post = postRepository.findById(id)
				.orElseThrow(() -> new PostNotFoundException(id));

		return modelMapper.map(post, PostDto.class);
	}

	@Override
	public void addLike(String postId) {
		Post post = postRepository.findById(postId)
				.orElseThrow(() -> new PostNotFoundException(postId));

		post.addLike();

		postRepository.save(post);
	}

	@Override
	public List<PostDto> findPostsByAuthor(String author) {
		Stream<Post> posts = postRepository.findAllByAuthor(author);

		return posts.map(p -> modelMapper.map(p, PostDto.class)).toList();
	}

	@Override
	public PostDto addComment(String postId, String user, AddCommentDto addCommentDto) {
		Post post = postRepository.findById(postId)
				.orElseThrow(() -> new PostNotFoundException(postId));

		Comment comment = modelMapper.map(addCommentDto, Comment.class);

		comment.setUser(user);

		post.getComments().add(comment);

		post = postRepository.save(post);

		return modelMapper.map(post, PostDto.class);
	}

	@Override
	public PostDto deletePost(String id) {
		Post post = postRepository.findById(id)
				.orElseThrow(() -> new PostNotFoundException(id));

		postRepository.delete(post);

		return modelMapper.map(post, PostDto.class);
	}

	@Override
	public List<PostDto> findPostsByTags(String[] tags) {
		Stream<Post> posts = postRepository.findAllByTagsIn(tags);

		return posts.map(p -> modelMapper.map(p, PostDto.class)).toList();
	}

	@Override
	public List<PostDto> findPostsByPeriod(PeriodDto periodDto) {
		Stream<Post> posts = postRepository.findAllByDateCreatedBetween(
				LocalDateTime.of(periodDto.getDateFrom(), LocalTime.MIN),
				LocalDateTime.of(periodDto.getDateTo(), LocalTime.MAX));

		return posts.map(p -> modelMapper.map(p, PostDto.class)).toList();
	}

	@Override
	public PostDto updatePost(String id, UpdatePostDto updatePostDto) {
		Post post = postRepository.findById(id)
				.orElseThrow(() -> new PostNotFoundException(id));

		modelMapper.map(updatePostDto, post);

		post = postRepository.save(post);

		return modelMapper.map(post, PostDto.class);
	}
}
