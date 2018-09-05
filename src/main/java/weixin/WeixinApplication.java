package weixin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "weixin")
public class WeixinApplication {

    public static void main(String[] args) {
        SpringApplication.run(WeixinApplication.class, args);
    }
}
