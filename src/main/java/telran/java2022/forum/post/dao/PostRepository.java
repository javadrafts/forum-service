package telran.java2022.forum.post.dao;

import java.time.LocalDateTime;
import java.util.stream.Stream;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import telran.java2022.forum.post.model.Post;

@Repository
public interface PostRepository extends CrudRepository<Post, String> {
	Stream<Post> findAllByAuthor(String author);

	Stream<Post> findAllByTagsIn(String... tags);

	Stream<Post> findAllByDateCreatedBetween(LocalDateTime dateFrom, LocalDateTime dateTo);
}
