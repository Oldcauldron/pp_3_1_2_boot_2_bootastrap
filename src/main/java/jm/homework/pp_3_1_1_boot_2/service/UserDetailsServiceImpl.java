package jm.homework.pp_3_1_1_boot_2.service;

import jm.homework.pp_3_1_1_boot_2.dao.RoleDao;
import jm.homework.pp_3_1_1_boot_2.dao.UserDao;
import jm.homework.pp_3_1_1_boot_2.model.archive.PreparedRoles;
import jm.homework.pp_3_1_1_boot_2.model.Role;
import jm.homework.pp_3_1_1_boot_2.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService, UserService, RoleService {

    private final RoleDao roleDao;
    private final UserDao userDao;
    private final Environment env;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public UserDetailsServiceImpl(RoleDao roleDao, UserDao userDao, Environment env, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.roleDao = roleDao;
        this.userDao = userDao;
        this.env = env;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public Role getRole(String role) {
        return roleDao.findByRole(role);
    }

    @Override
    public Set<Role> getAllRoles() {
        return new HashSet<>(roleDao.findAll());
    }

    @Override
    public List<User> allUsers() {
        return userDao.findAll();
    }

    @Override
    public void addUser(User user) {
        Set<Role> defaultRoles = Collections.singleton(getRole("ROLE_USER"));
        String passCrypt = cryptPass(user.getPassword());
        user.setPassword(passCrypt);
        if (user.getRoles().size() == 0) {
            user.setRoles(defaultRoles);
        }
        userDao.save(user);
    }

    @Override
    public void updateUser(User user) {
        user.setPassword(cryptPass(user.getPassword()));
        userDao.save(user);
    }

    @Override
    public boolean isExistingUser(User user) {
        return userDao.existsById(user.getId());
    }

    @Override
    public boolean isExistingUserByEmail(String email) {
        try {
            User user = userDao.findByEmail(email);
            return isExistingUser(user);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public User showById(long id) {
        return userDao.findById(id).orElseThrow(() -> new UsernameNotFoundException("User no found. This exception from UserDetailsServiceImpl - showById"));
    }

    @Override
    public void deleteUserById(long id) {
        userDao.deleteById(id);
    }


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userDao.findByEmail(email);
    }

    @Override
    public User findByEmail(String email) {
        return userDao.findByEmail(email);
    }

    public String cryptPass(String pass) {
        return bCryptPasswordEncoder.encode(pass);
    }
}

