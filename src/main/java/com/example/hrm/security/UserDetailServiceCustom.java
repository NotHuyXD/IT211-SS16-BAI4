package com.example.hrm.security;

import com.example.hrm.entity.User;
import com.example.hrm.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

// Đánh dấu đây là một Service để Spring Boot tự động quản lý (IoC Container)
@Service
public class UserDetailServiceCustom implements UserDetailsService {

    // Tiêm (Inject) UserRepository vào để tương tác với Database
    private final UserRepository userRepository;

    @Autowired
    public UserDetailServiceCustom(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // Ghi đè phương thức cốt lõi của Spring Security
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 1. Tìm kiếm người dùng trong Database
        // Sử dụng orElseThrow của Optional để ném ra ngoại lệ ngay lập tức nếu kết quả là null
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Không tìm thấy tài khoản: " + username));

        // 2. Chuyển đổi quyền hạn
        // Nối thêm tiền tố "ROLE_" để tương thích hoàn toàn với các hàm phân quyền như hasRole()
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + user.getRole());

        // 3. Đóng gói Entity User và quyền hạn vào UserPrincipal để trả về cho Spring Security
        // Vì ở đây mỗi user chỉ có 1 role, ta dùng Collections.singletonList để tạo List chứa 1 phần tử
        return new UserPrincipal(user, Collections.singletonList(authority));
    }
}