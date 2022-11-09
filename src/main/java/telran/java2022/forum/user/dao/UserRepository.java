package telran.java2022.forum.user.dao;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import telran.java2022.forum.user.model.User;

@Repository
public interface UserRepository extends CrudRepository<User, String> {

}
