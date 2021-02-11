package jm.homework.pp_3_1_1_boot_2.controller;

import jm.homework.pp_3_1_1_boot_2.model.Role;
import jm.homework.pp_3_1_1_boot_2.model.User;
import jm.homework.pp_3_1_1_boot_2.service.RoleService;
import jm.homework.pp_3_1_1_boot_2.service.SecurityService;
import jm.homework.pp_3_1_1_boot_2.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Controller
@RequestMapping("")
public class UserControllerNew {

    private final UserDetailsService userDetailsService;
    private final UserService userService;
    private final RoleService roleService;
    private final SecurityService securityService;

    @Autowired
    public UserControllerNew(@Qualifier("userDetailsServiceImpl")
                                  UserDetailsService userDetailsService,
                          UserService userService,
                          RoleService roleService,
                          SecurityService securityService) {
        this.userDetailsService = userDetailsService;
        this.userService = userService;
        this.roleService = roleService;
        this.securityService = securityService;
    }


    // --------------- CONTROLLERS ------------------------------

    @GetMapping(value = "/user-b/{id}")
    public String getUserPage(@PathVariable("id") long id, Model model) {
        allNecessaryAddingToModel(model);
        return "user_b";
    }

    @PreAuthorize("@securityServiceImpl.preauthorizeFunc(#id, authentication)")
    @DeleteMapping(value = "/user-b/{id}")
    public String deleteUser(@PathVariable("id") long id, Model model) {
        userService.deleteUserById(id);
        return "redirect:/admin-b";
    }

    @PreAuthorize("@securityServiceImpl.preauthorizeFunc(#id, authentication)")
    @PatchMapping(value = "/user-b/{id}")
    public String getUserFormSecond(@ModelAttribute("user") User user,
                                    @PathVariable("id") long id,
                                    Model model,
                                    RedirectAttributes redirectAttributes) {
        boolean err = false;
        User oldUser = userService.showById(id);

        boolean emailEmpty = user.getEmail().isEmpty();
        boolean nameEmpty = user.getName().isEmpty();
        boolean passwordEmpty = user.getPassword().isEmpty();

        if ((!oldUser.getEmail().equals(user.getEmail()))
                && userService.isExistingUserByEmail(user.getEmail())) {
            redirectAttributes.addFlashAttribute("errorExist", "this email is already exist");
            err = true;
        }

        if (err || emailEmpty || nameEmpty || passwordEmpty) {
            redirectAttributes.addFlashAttribute("emailEmpty", emailEmpty);
            redirectAttributes.addFlashAttribute("nameEmpty", nameEmpty);
            redirectAttributes.addFlashAttribute("passwordEmpty", passwordEmpty);
            return "redirect:/admin-b";
        }
        userService.updateUser(user);
        return "redirect:/admin-b";
    }


    @GetMapping(value = "/admin-b")
    public String getAdminPage(Model model) {
        allNecessaryAddingToModel(model);
        return "admin_b";
    }


    private Model allNecessaryAddingToModel(Model model) {
        User user = securityService.getAuthUser();

        String email = "";
        Set<String> roles = new HashSet<>();
        if (user.getId() != null) {
            email = user.getUsername();
            roles = user.getRoles().stream().map(Role::getRole).collect(Collectors.toSet());
        }

        if (!model.containsAttribute("user")) {
            model.addAttribute("user", new User());
        }

        List<User> listUsers = userService.allUsers();

        model.addAttribute("rolesAll", roleService.getAllRoles());
        model.addAttribute("listUsers", listUsers);
        model.addAttribute("email", email);
        model.addAttribute("roles", roles);
        model.addAttribute("authUser", user);
        return model;
    }





}
