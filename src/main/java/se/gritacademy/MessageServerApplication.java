package se.gritacademy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import jakarta.persistence.*;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.Optional;
import java.util.regex.Pattern;

@SpringBootApplication
public class MessageServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(MessageServerApplication.class, args);
    }
}

@Entity
class UserInfo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String email;
    private String password;
    private String role = "user";

    public UserInfo() {}
    public UserInfo(String email, String password, String role) {
        this.email = email;
        this.password = password;
        this.role = role;
    }

    public String getEmail() { return email; }
    public String getPassword() { return password; }
    public String getRole() { return role; }

}

@Entity
class Message {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String sender;
    private String recipient;
    private String message;

    private Instant date;

    public Message() {}

    public Message(String sender, String recipient, String message) {
        this.sender = sender;
        this.recipient = recipient;
        this.message = message;
        this.date = Instant.now();
    }

    public Long getId() { return id; }
    public String getSender() { return sender; }
    public String getRecipient() { return recipient; }
    public String getMessage() { return message; }

    public String getDate() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.of("UTC"));

        return formatter.format(date);
    }
}

interface MessageRepository extends JpaRepository<Message, Long>{
    List<Message> findByRecipient(String Recipient);
}

interface UserRepository extends JpaRepository<UserInfo, Long> {
    Optional<UserInfo> findByEmail(String email);
    List<UserInfo> findAll();
}

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MessageRepository messageRepository;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestParam String email, @RequestParam String password) {
        System.out.println("/register körs");
        if (userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already in use");
        }

        String passwordPattern = "^(?=.*[A-Z])(?=.*[a-z]).{12,}$";

        Pattern pattern = Pattern.compile(passwordPattern);

        if (!pattern.matcher(password).matches()) {
            System.out.println("Felaktigt lösenord: " + password);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("The password does not meet the requirements. It must be at least 12 characters long and contain at least one uppercase letter and one lowercase letter.");
        }

        String hashedPassword = PasswordHasher.hashPassword(password);


        // Spara användaren
        userRepository.save(new UserInfo(email, hashedPassword, "user"));
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String email, @RequestParam String password) {
        Optional<UserInfo> userOpt = userRepository.findByEmail(email);
        if (userOpt.isPresent()) {
            UserInfo user = userOpt.get();

            String hashedInputPassword = PasswordHasher.hashPassword(password);

            if (hashedInputPassword.matches(user.getPassword())) {
                String token = generateJwtToken(user);
                return ResponseEntity.ok(token);
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
    }

    @GetMapping("/messages")
    public ResponseEntity<List<Message>> getMessages(@RequestHeader("Authorization") String token) {
        Claims claims = parseJwtToken(token.replace("Bearer ", ""));

        if (claims == null) {
            System.out.println("Claim is null");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }


        String userEmail = claims.getSubject();

        List<Message> messages = messageRepository.findByRecipient(userEmail);

        return  ResponseEntity.ok(messages);
    }

    @GetMapping("/users")
        public ResponseEntity<List<String>> getUsers(@RequestHeader("Authorization") String token) {
        parseJwtToken(token.replace("Bearer ", ""));

        List<String> userList = userRepository.findAll().stream().map(UserInfo::getEmail).toList();
        return ResponseEntity.ok(userList);
    }

    @PostMapping("/messages")
    public ResponseEntity<String> sendMessage(@RequestHeader("Authorization") String token, @RequestParam String recipient, @RequestParam String message) {
        Claims claims = parseJwtToken(token.replace("Bearer ", ""));

        if (claims == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Claim is null");
        }

        if (message.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Message is empty");
        }
        else if(recipient.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Recipient is empty");
        }

        String sender = claims.getSubject();

        Message newMessage = new Message(sender, recipient, message);

        messageRepository.save(newMessage);

        return ResponseEntity.ok("Message sent to " + newMessage.getRecipient());
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout() {
        return ResponseEntity.ok("Logged out successfully");
    }

    private static final Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    private String generateJwtToken(UserInfo user) {

        long expirationTime = 1000 * 60 * 60; //Utgångsdatum, 1 h

        Date expirationDate = new Date(System.currentTimeMillis() + expirationTime);

        return Jwts.builder()
                .setSubject(user.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(expirationDate)
                .signWith(secretKey)
                .compact();
    }

    private Claims parseJwtToken(String token) {
        try {
            Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256); //hemlig nyckel
            return Jwts.parserBuilder()
                    .setSigningKey(key) //verifiering token med nyckeln
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            return null;
        }
    }
    public class PasswordHasher {
        public static String hashPassword(String password) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashedBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
                return bytesToHex(hashedBytes);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("SHA-256 is not supported", e);
            }
        }

        private static String bytesToHex(byte[] bytes) {
            StringBuilder hexString = new StringBuilder();
            for (byte b : bytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        }

    }
}